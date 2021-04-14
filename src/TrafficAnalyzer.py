import threading
import logging
import time
import datetime
from src.utils.utils import restart_on_error, check_ip_blacklist

class TrafficAnalyzer():
    """Parses the data obtained from Traffic Monitor and sent to HostState, detects anomalous behavior over time"""
    def __init__(self, host_state):
        self.host_state = host_state
        self.active = False
        self.TIME_WINDOW = self.host_state.config.get_config("TIME_WINDOW")

        self.thread = threading.Thread(target=self.safe_run_analyzer)
        self.thread.daemon = True
        self.lock = threading.Lock()

        self.start_time = 0
        self.stop_time = 0
    def start(self):
        with self.lock:
            self.active = True
        logging.info("[Analyzer] Traffic analyzer starting")
        self.thread.start()


    def stop(self):
        with self.lock:
            self.active = False
        logging.info("[Analyzer] Last analyzer run")
        self.analyzer(quitting_run=True)
        logging.info("[Analyzer] Traffic analyzer stopping")
        self.thread.join()

    def sleep(self, seconds):
        for _ in range(seconds):
            if not self.active:
                break
            time.sleep(1)

    def count_NXDOMAIN_per_IP(self):
        """
        Analyze NXDOMAINS in the last time window,
        sends an alert to the alert manager if there are more than threshold per time window
        """
        # TODO: fix an error: 67000 NXDOMAINS with 2700 packets?
        pDNS = self.host_state.passive_DNS.copy()
        queried_domains = self.host_state.queried_domains.copy()
        nxdomains_counts_per_IP = {}
        for ip in queried_domains:
            nxdomains_counts_per_IP[ip] = 0
            for pair in queried_domains[ip]:
                timestamp = pair[0]
                domain = pair[1]
                if timestamp > self.stop_time:
                    break
                elif timestamp < self.start_time:
                    continue
                else:
                    if domain in pDNS:
                        if len(pDNS[domain]) == 0:
                            nxdomains_counts_per_IP[ip] += 1
        return nxdomains_counts_per_IP

    def analyze_flows(self, flag):
        """counts packets with the exact same flags sent by a host to a remote IP in the time window"""
        # keys are FlowKey, values are SYN counts in the time window
        flag_counts = {}
        contacted_IPs = {}
        flows = self.host_state.flows.copy()
        for flow in flows:
            # read packets from end to beginning
            packets = reversed(flows[flow])
            for p in packets:
                if p.inbound: continue
                if p.timestamp > self.stop_time:
                    continue
                elif p.timestamp < self.start_time:
                    break
                if flag == "S":
                    # do not count SA as SYN packets
                    if "S" in p.flags and "A" not in p.flags:
                        flag_counts[flow] = flag_counts.get(flow, 0) + 1
                        ip_src = getattr(flow,"IP_src")
                        ip_dst = getattr(flow,"IP_dst")
                        contacted_IPs.setdefault(ip_src, set()).add(ip_dst)
                else:
                    if p.flags == flag:
                        flag_counts[flow] = flag_counts.get(flow, 0) + 1
                        ip_src = getattr(flow,"IP_src")
                        ip_dst = getattr(flow,"IP_dst")
                        contacted_IPs.setdefault(ip_src, set()).add(ip_dst)
        return flag_counts, contacted_IPs

    def get_scores_of_contacted_domains(self):
        domain_scores = self.host_state.domain_scores.copy()
        queried_domains = self.host_state.queried_domains.copy()
        scores_per_IP = {}
        contacted_domains = {}
        for ip in queried_domains:
            contacted_domains[ip] = set()
            scores_per_IP[ip] = []
            # contacted_domains[ip] = set([p[1] for p in queried_domains[ip]])
            for p in queried_domains[ip]:
                timestamp = p[0]
                domain = p[1]
                if timestamp > self.stop_time:
                    break
                if timestamp <= self.stop_time and timestamp >= self.start_time:
                    if domain not in contacted_domains[ip]:
                        contacted_domains[ip].add(domain)
                        if domain in domain_scores:
                            scores_per_IP[ip].append(domain_scores[domain])

        DOMAIN_SCORE_THRESHOLD = self.host_state.config.get_config("DOMAIN_SCORE_THRESHOLD")
        for ip in scores_per_IP:
            bad_scores = [s for s in scores_per_IP[ip] if s > DOMAIN_SCORE_THRESHOLD]
            bad_scores_count = len(bad_scores)
            if bad_scores_count > self.host_state.config.get_config("MAX_DOMAIN_COUNT"):
                self.host_state.alert_manager.new_alert_domains(ip, self.start_time, self.stop_time, bad_scores_count, DOMAIN_SCORE_THRESHOLD)
        return scores_per_IP


    def detect_nxdomain_alert(self, nxdomain_counts):
        """Raises alert if one host generated too much NXDOMAIN"""
        threshold = self.host_state.config.get_config("MAX_NXDOMAIN")
        for ip in nxdomain_counts:
            if nxdomain_counts[ip] > threshold:
                timestamp_start = self.start_time
                timestamp_end = self.stop_time
                nxcount = nxdomain_counts[ip]
                logging.debug("ALERT: %d NXDOMAIN from host %s", nxcount, ip)
                self.host_state.alert_manager.new_alert_nxdomain(ip, timestamp_start, timestamp_end, nxcount, threshold)

    def detect_vertical_port_scan(self, syn_counts):
        """
        Counts unique ports contacted per key (flow["IP_src"], flow["IP_dst"])
        """
        ports_contacted = {}
        for flow in syn_counts:
            key = (getattr(flow,"IP_src"), getattr(flow,"IP_dst"))
            if key not in ports_contacted:
                ports_contacted[key] = set()
            ports_contacted[key].add(getattr(flow, "port_dst"))
        for key in ports_contacted:
            if len(ports_contacted[key]) > self.host_state.config.get_config("MAX_PORTS_PER_HOST"):
                logging.debug(f"ALERT: port scanning on {key}: {len(ports_contacted[key])} port contacted ", ports_contacted[key])
                host_IP = key[0]
                target_IP = key[1]
                timestamp_start = self.start_time
                timestamp_end = self.stop_time
                port_count = len(ports_contacted[key])
                self.host_state.alert_manager.new_alert_vertical_portscan(host_IP, target_IP, timestamp_start, timestamp_end, port_count)

    #TODO: horizontal port scan: detect same port on multiple IPs, but whitelist some?
    def detect_horizontal_port_scan(self, syn_counts):
        ip_contacted = {}
        for flow in syn_counts:
            key = (getattr(flow,"IP_src"), getattr(flow,"port_dst"))
            if key not in ip_contacted:
                ip_contacted[key] = set()
            ip_contacted[key].add(getattr(flow, "IP_dst"))
        for key in ip_contacted:
            if key[1] not in self.host_state.config.get_config("WHITELIST_PORTS") and len(ip_contacted[key]) > self.host_state.config.get_config("MAX_IP_PER_PORT"):
                host_IP = key[0]
                port_dst = key[1]
                timestamp_start = self.start_time
                timestamp_end = self.stop_time
                ip_count = len(ip_contacted[key])
                logging.debug("ALERT: port scanning on port %s: %s IP contacted ", port_dst, ip_count)
                self.host_state.alert_manager.new_alert_horizontal_portscan(host_IP, port_dst, timestamp_start, timestamp_end, ip_count)

    def detect_dos_on_port(self, syn_counts):
        """Detects if one IP:port combination has received too many SYN packets"""
        syn_on_port = {}
        # merge by IP_src, IP_dst, port_dst (do use the source port in key)
        for flow in syn_counts:
            key = (getattr(flow,"IP_src"), getattr(flow,"IP_dst"), getattr(flow, "port_dst"))
            syn_on_port[key] = syn_on_port.get(key, 0) + syn_counts[flow]
        threshold = self.host_state.config.get_config("MAX_CONNECTIONS_PER_PORT")
        for key in syn_on_port:
            if syn_on_port[key] > threshold:
                host_IP = key[0]
                target_IP = key[1]
                domain = self.host_state.reverse_pDNS(target_IP)
                logging.debug(f"ALERT: DDoS {host_IP} has initiated {syn_on_port[key]} connections with {target_IP}:{key[2]} ({domain})")
                timestamp_start = self.start_time
                timestamp_end = self.stop_time
                conn_count = syn_on_port[key]
                threshold
                self.host_state.alert_manager.new_alert_dos(host_IP, target_IP, timestamp_start, timestamp_end, conn_count, threshold)


    def detect_contacted_ip(self, contacted_ips):
        pDNS = self.host_state.passive_DNS.copy()
        blacklisted_ips = self.host_state.blacklisted_ips.copy()

        contacted_with_no_DNS = []
        for ip_src in contacted_ips:
            for ip_dst in contacted_ips[ip_src]:
                # check if IP is blacklisted
                if ip_dst not in blacklisted_ips:
                    if self.host_state.config.get_config("ENABLE_BLACKLIST_QUERY"):
                        is_in_blacklist = check_ip_blacklist(ip_dst)
                    else:
                        is_in_blacklist = False
                    self.host_state.blacklisted_ips[ip_dst] = is_in_blacklist
                else:
                    is_in_blacklist = blacklisted_ips[ip_dst]
                if is_in_blacklist:
                    logging.debug("ALERT: %s has contacted %s which is blacklisted", ip_src, ip_dst)
                    self.host_state.alert_manager.new_alert_blacklisted_ip(ip_src, ip_dst, self.start_time)

                # check if IP was in pDNS
                found = False
                for domain in pDNS:
                    if ip_dst in pDNS[domain]:
                        found = True
                        break
                if not found:
                    contacted_with_no_DNS.append((ip_src,ip_dst))
                    self.host_state.alert_manager.new_alert_no_dns(ip_src, ip_dst, self.start_time)



    def detect_alerts(self, start, stop):
        self.start_time = start
        self.stop_time = stop
        h1 = datetime.datetime.fromtimestamp(start).strftime('%H:%M:%S')
        h2 = datetime.datetime.fromtimestamp(stop).strftime('%H:%M:%S')
        logging.debug("[Analyzer] %s: Alert detection between %s and %s", self.host_state.capture_file.split("/")[-1], h1, h2)
        nxdomain_counts = self.count_NXDOMAIN_per_IP()
        syn_counts, contacted_ips = self.analyze_flows("S")
        udp_counts, contacted_ips_udp = self.analyze_flows("UDP")
        domains_scores = self.get_scores_of_contacted_domains()
        # analyze data and raise alerts if something is suspicious
        self.detect_nxdomain_alert(nxdomain_counts)
        self.detect_vertical_port_scan(syn_counts)
        self.detect_horizontal_port_scan(syn_counts)
        self.detect_dos_on_port(syn_counts)
        self.detect_dos_on_port(udp_counts)
        self.detect_contacted_ip(contacted_ips)


    def analyzer(self, quitting_run=False):
        self.TIME_WINDOW = self.host_state.config.get_config("TIME_WINDOW")
        if self.host_state.online:
            stop_time = time.time()
            start_time = stop_time - self.TIME_WINDOW
            h1 = datetime.datetime.fromtimestamp(start_time).strftime('%H:%M:%S')
            h2 = datetime.datetime.fromtimestamp(stop_time).strftime('%H:%M:%S')
            logging.debug("[Analyzer] Analyzing data to detect alerts between %s and %s (window = %d)", h1, h2, self.TIME_WINDOW)
            self.detect_alerts(start_time, stop_time)
        else:
            if self.host_state.first_timestamp > 0:
                # if some data has been uploaded
                if self.host_state.last_timestamp - self.host_state.first_timestamp > self.TIME_WINDOW or quitting_run:
                    # if there is at least one time window in all the uploaded data or if we are in the last run
                    # in the last run, run a window no matter if incomplete
                    if self.start_time == 0:
                        # if it is the first ever time window, start of first timestamp, else use previous start time
                        start_windows = self.host_state.first_timestamp
                    else:
                        #start where we left the last time window
                        start_windows = self.stop_time
                    # at this point, start windows points where the last time window ended
                    # place stop and start there, and if there
                    start = start_windows
                    while start + self.TIME_WINDOW < self.host_state.last_timestamp:
                        stop = start + self.TIME_WINDOW
                        self.detect_alerts(start, stop)
                        # move start to stop to check if next time window is possible
                        start = stop

                    if quitting_run:
                        #if this is the quitting run, run from start to end, even if last_timestamp is inferior
                        stop = start + self.TIME_WINDOW
                        self.detect_alerts(start, stop)
            logging.debug("[Analyzer] End of analyzer iteration (file %s) ", self.host_state.capture_file.split("/")[-1])





    def analyzer_loop(self):
        while self.active:
            self.analyzer()
            iteration_time = self.host_state.config.get_config("DATABASE_UPDATE_DELAY")
            self.sleep(iteration_time)

    def safe_run_analyzer(self):
        restart_on_error(self.analyzer_loop)