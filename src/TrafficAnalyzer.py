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

    def count_NXDOMAIN_per_IP(self, start_time, stop_time):
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
                if ts > stop_time:
                    continue
                elif ts < start_time:
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

    def count_TCP_flag_packets(self, flag, start_time, stop_time):
        """counts packets with the exact same flags sent by a host to a remote IP in the time window"""
        # keys are FlowKey, values are SYN counts in the time window
        flag_counts = {} 
        for flow in self.host_state.flows:
            # read packets from end to beginning
            packets = reversed(self.host_state.flows[flow])
            for p in packets:
                if p.timestamp > stop_time:
                    continue
                elif p.timestamp < start_time:
                    break
                if p.flags == flag:
                    flag_counts[flow] = flag_counts.get(flow, 0) + 1
        return flag_counts


    def detect_nxdomain_alert(self, nxdomain_counts):
        """Raises alert if one host generated too much NXDOMAIN"""
        for ip in nxdomain_counts:
            if nxdomain_counts[ip] > MAX_NXDOMAIN:
                print("ALERT: too many NXDOMAIN from host ", ip)
                # TODO: raise alert

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
            if len(ports_contacted[key]) > MAX_PORTS_PER_HOST:
                print(f"ALERT: port scanning on {key}: {len(ports_contacted[key])} port contacted ", ports_contacted[key])
                # TODO: raise alert

    def detect_ddos_on_port(self, syn_counts):
        """Detects if one IP:port combination has received too many SYN packets"""
        syn_on_port = {}
        # merge by IP_src, IP_dst, port_dst (do use the source port in key)
        for flow in syn_counts:
            key = (getattr(flow,"IP_src"), getattr(flow,"IP_dst"), getattr(flow, "port_dst"))
            syn_on_port[key] = syn_on_port.get(key, 0) + syn_counts[flow]
        for key in syn_on_port:
            if syn_on_port[key] > MAX_CONNECTIONS_PER_PORT:
                print(f"ALERT: DDoS {key[0]} has initiated {syn_on_port[key]} connections with {key[1]}:{key[2]}")
                # TODO: raise alert



    def detect_alerts(self, start_time, stop_time):
        if start_time > stop_time:
            start_time, stop_time = stop_time, start_time
        # count data
        nxdomain_counts = self.count_NXDOMAIN_per_IP(start_time, stop_time)
        syn_counts = self.count_TCP_flag_packets("S", start_time, stop_time)
        
        # analyze data and raise alerts if something is suspicious
        self.detect_nxdomain_alert(nxdomain_counts)
        self.detect_vertical_port_scan(syn_counts)
        self.detect_ddos_on_port(syn_counts)

    def analyzer(self):
        while self.active:
            # TODO: if scanning PCAP, do not use time.time() !
            stop_time = time.time()
            start_time = stop_time - self.TIME_WINDOW
            self.detect_alerts(start_time, stop_time)
            self.sleep(self.iteration_time)

    def safe_run_analyzer(self):
        restart_on_error(self.analyzer)