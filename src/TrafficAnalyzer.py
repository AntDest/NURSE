import threading
import logging
import time
from src.utils.utils import restart_on_error
from config import TIME_WINDOW, MAX_CONNECTIONS_PER_PORT, MAX_NXDOMAIN, MAX_PORTS_PER_HOST, MAX_IP_PER_PORT, WHITELIST_PORTS, DATABASE_UPDATE_DELAY, DOMAIN_SCORE_THRESHOLD, MAX_DOMAIN_COUNT

class TrafficAnalyzer():
    """Parses the data obtained from Traffic Monitor and sent to HostState, detects anomalous behavior over time"""
    def __init__(self, host_state):
        self.host_state = host_state
        self.active = False
        self.TIME_WINDOW = TIME_WINDOW
        self.iteration_time = DATABASE_UPDATE_DELAY

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
        logging.info("[Analyzer] Traffic analyzer stopping")
        with self.lock:
            self.active = False
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
        pDNS = self.host_state.passive_DNS.copy()
        queried_domains = self.host_state.queried_domains.copy()
        nxdomains_counts_per_IP = {}
        for ip in queried_domains:
            for pair in queried_domains[ip]:
                domain = pair[1]
                if domain in pDNS:
                    if pDNS[domain] == []:
                        nxdomains_counts_per_IP[ip] = nxdomains_counts_per_IP.get(ip, 0) + 1
        return nxdomains_counts_per_IP

    def analyze_flows(self, flag):
        """counts packets with the exact same flags sent by a host to a remote IP in the time window"""
        # keys are FlowKey, values are SYN counts in the time window
        flag_counts = {} 
        contacted_IPs = {}
        for flow in self.host_state.flows.copy():
            # read packets from end to beginning
            packets = reversed(self.host_state.flows[flow])
            for p in packets:
                if p.timestamp > self.stop_time:
                    continue
                elif p.timestamp < self.start_time:
                    break
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

        for ip in scores_per_IP:
            bad_scores = [s for s in scores_per_IP[ip] if s > DOMAIN_SCORE_THRESHOLD]
            bad_scores_count = len(bad_scores)
            if bad_scores_count > MAX_DOMAIN_COUNT:
                self.host_state.alert_manager.new_alert_domains(ip, self.start_time, self.stop_time, bad_scores_count, DOMAIN_SCORE_THRESHOLD)
        return scores_per_IP


    def detect_nxdomain_alert(self, nxdomain_counts):
        """Raises alert if one host generated too much NXDOMAIN"""
        for ip in nxdomain_counts:
            if nxdomain_counts[ip] > MAX_NXDOMAIN:
                print("ALERT: too many NXDOMAIN from host ", ip)
                timestamp_start = self.start_time
                timestamp_end = self.stop_time
                nxcount = nxdomain_counts[ip]
                self.host_state.alert_manager.new_alert_nxdomain(ip, timestamp_start, timestamp_end, nxcount)

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
        # print(ports_contacted)
        for key in ports_contacted:
            if len(ports_contacted[key]) > MAX_PORTS_PER_HOST:
                print(f"ALERT: port scanning on {key}: {len(ports_contacted[key])} port contacted ", ports_contacted[key])
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
            if key[1] not in WHITELIST_PORTS and len(ip_contacted[key]) > MAX_IP_PER_PORT:
                host_IP = key[0]
                port_dst = key[1]
                timestamp_start = self.start_time
                timestamp_end = self.stop_time
                ip_count = len(ip_contacted[key])
                self.host_state.alert_manager.new_alert_horizontal_portscan(host_IP, port_dst, timestamp_start, timestamp_end, ip_count)

    def detect_dos_on_port(self, syn_counts):
        """Detects if one IP:port combination has received too many SYN packets"""
        syn_on_port = {}
        # merge by IP_src, IP_dst, port_dst (do use the source port in key)
        for flow in syn_counts:
            key = (getattr(flow,"IP_src"), getattr(flow,"IP_dst"), getattr(flow, "port_dst"))
            syn_on_port[key] = syn_on_port.get(key, 0) + syn_counts[flow]
        for key in syn_on_port:
            if syn_on_port[key] > MAX_CONNECTIONS_PER_PORT:
                host_IP = key[0]
                target_IP = key[1]
                domain = self.host_state.reverse_pDNS(target_IP)
                print(f"ALERT: DDoS {target_IP} has initiated {syn_on_port[key]} connections with {target_IP}:{key[2]} ({domain})")
                timestamp_start = self.start_time
                timestamp_end = self.stop_time
                conn_count = syn_on_port[key]
                self.host_state.alert_manager.new_alert_dos(host_IP, target_IP, timestamp_start, timestamp_end, conn_count)


    def detect_contacted_ip_without_dns(self, contacted_ips):
        pDNS = self.host_state.passive_DNS.copy()
        contacted_with_no_DNS = []
        for ip_src in contacted_ips:
            for ip_dst in contacted_ips[ip_src]:
                found = False
                for domain in pDNS:
                    if ip_dst in pDNS[domain]:
                        found = True 
                        break
                if not found:
                    contacted_with_no_DNS.append((ip_src,ip_dst))
                    self.host_state.alert_manager.new_alert_no_dns(ip_src, ip_dst, self.start_time)


    def detect_alerts(self, start_time, stop_time):
        self.start_time = start_time
        self.stop_time = stop_time
        nxdomain_counts = self.count_NXDOMAIN_per_IP()
        syn_counts, contacted_ips = self.analyze_flows("S")
        domains_scores = self.get_scores_of_contacted_domains()

        # analyze data and raise alerts if something is suspicious
        self.detect_nxdomain_alert(nxdomain_counts)
        self.detect_vertical_port_scan(syn_counts)
        self.detect_dos_on_port(syn_counts)
        self.detect_contacted_ip_without_dns(contacted_ips)

    def analyzer(self):
        import datetime
        while self.active:
            logging.debug("[Analyzer] New iteration")
            # TODO: if scanning PCAP, do not use time.time() !
            if self.host_state.online:
                stop_time = time.time()
                start_time = stop_time - self.TIME_WINDOW
                h1 = datetime.datetime.fromtimestamp(start_time).strftime('%H:%M:%S')
                h2 = datetime.datetime.fromtimestamp(stop_time).strftime('%H:%M:%S')
                logging.debug("[Analyzer] Analyzing data to detect alerts between %s and %s (window = %d)", h1, h2, self.TIME_WINDOW)
                self.detect_alerts(start_time, stop_time)
            else:
                new_stop_time = self.host_state.last_timestamp
                if new_stop_time > 0:
                    if self.stop_time > 0:
                        prev_stop_time = self.stop_time
                    else:
                        # first iteration, do only one time window, because no previous stop time is set
                        prev_stop_time = new_stop_time - self.TIME_WINDOW
                    for start_time in range(prev_stop_time, new_stop_time, self.TIME_WINDOW):
                        stop_time = start_time + self.TIME_WINDOW
                        h1 = datetime.datetime.fromtimestamp(start_time).strftime('"%m/%d/%Y, %H:%M:%S')
                        h2 = datetime.datetime.fromtimestamp(stop_time).strftime('"%m/%d/%Y, %H:%M:%S')
                        # logging.debug("[Analyzer] Analyzing data to detect alerts between %s and %s (window = %d)", h1, h2, self.TIME_WINDOW)
                        self.detect_alerts(start_time, stop_time)
            self.sleep(self.iteration_time)

    def safe_run_analyzer(self):
        restart_on_error(self.analyzer)