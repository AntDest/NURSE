import threading
import logging
import time
from src.utils.utils import restart_on_error
from config import TIME_WINDOW, MAX_CONNECTIONS_PER_PORT, MAX_NXDOMAIN, MAX_PORTS_PER_HOST, DATABASE_UPDATE_DELAY

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
            nxdomain_count = 0
            # read from the end, and break when timestamp is too old
            for query in reversed(queried_domains[ip]):
                ts = query[0]
                if ts > self.stop_time:
                    continue
                elif ts < self.start_time:
                    break

                domain = query[1]
                if domain not in pDNS:
                    # should not happen, but could with some bugs due to not deep enough copies
                    logging.error("[Analyzer] %s is in queried domains but not in pDNS")
                    return
                if len(pDNS[domain]) == 0:
                    nxdomain_count += 1
            nxdomains_counts_per_IP[ip] = nxdomain_count
        return nxdomains_counts_per_IP

    def count_TCP_flag_packets(self, flag):
        """counts packets with the exact same flags sent by a host to a remote IP in the time window"""
        # keys are FlowKey, values are SYN counts in the time window
        flag_counts = {} 
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
        return flag_counts


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
                self.host_state.alert_manager.new_alert_portscan(host_IP, target_IP, timestamp_start, timestamp_end, port_count)

    #TODO: horizontal port scan: detect same port on multiple IPs, but whitelist some?


    def detect_dos_on_port(self, syn_counts):
        """Detects if one IP:port combination has received too many SYN packets"""
        syn_on_port = {}
        # merge by IP_src, IP_dst, port_dst (do use the source port in key)
        for flow in syn_counts:
            key = (getattr(flow,"IP_src"), getattr(flow,"IP_dst"), getattr(flow, "port_dst"))
            syn_on_port[key] = syn_on_port.get(key, 0) + syn_counts[flow]
        for key in syn_on_port:
            if syn_on_port[key] > MAX_CONNECTIONS_PER_PORT:
                print(f"ALERT: DDoS {key[0]} has initiated {syn_on_port[key]} connections with {key[1]}:{key[2]}")
                host_IP = key[0]
                target_IP = key[1]
                timestamp_start = self.start_time
                timestamp_end = self.stop_time
                conn_count = syn_on_port[key]
                self.host_state.alert_manager.new_alert_dos(host_IP, target_IP, timestamp_start, timestamp_end, conn_count)



    def detect_alerts(self, start_time, stop_time):
        self.start_time = start_time
        self.stop_time = stop_time
        nxdomain_counts = self.count_NXDOMAIN_per_IP()
        syn_counts = self.count_TCP_flag_packets("S")
        
        # analyze data and raise alerts if something is suspicious
        self.detect_nxdomain_alert(nxdomain_counts)
        self.detect_vertical_port_scan(syn_counts)
        self.detect_dos_on_port(syn_counts)

    def analyzer(self):
        import datetime
        while self.active:
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
                    if new_stop_time > prev_stop_time:
                        print(prev_stop_time, new_stop_time)
                    for start_time in range(prev_stop_time, new_stop_time, self.TIME_WINDOW):
                        stop_time = start_time + self.TIME_WINDOW
                        h1 = datetime.datetime.fromtimestamp(start_time).strftime('%H:%M:%S')
                        h2 = datetime.datetime.fromtimestamp(stop_time).strftime('%H:%M:%S')
                        # logging.debug("[Analyzer] Analyzing data to detect alerts between %s and %s (window = %d)", h1, h2, self.TIME_WINDOW)
                        self.detect_alerts(start_time, stop_time)
            self.sleep(self.iteration_time)

    def safe_run_analyzer(self):
        restart_on_error(self.analyzer)