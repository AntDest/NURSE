import threading
import logging
import time
from src.utils.utils import safe_run


class TrafficAnalyzer():
    """Parses the data obtained from Traffic Monitor and sent to HostState, detects anomalous behavior over time"""
    def __init__(self, host_state):
        self.host_state = host_state
        self.active = False
        self.TIME_WINDOW = 30
        self.iteration_time = self.TIME_WINDOW / 2

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

    def analyze_NXDOMAIN(self):
        # analyze NXDOMAINS:
        logging.debug("ANALYZING NXDOMAINS") 
        pDNS = self.host_state.passive_DNS.copy()
        queried_domains = self.host_state.queried_domains.copy()
        start_timestamp = time.time() - self.TIME_WINDOW
        nxdomains_counts_per_IP = {}
        for ip in queried_domains:
            nxdomain_count = 0
            # read from the end, and break when timestamp is too old
            for query in reversed(queried_domains[ip]):
                ts = query[0]
                domain = query[1]
                if ts < start_timestamp:
                    break
                else:
                    if len(pDNS[domain]) == 0:
                        nxdomain_count += 1
            nxdomains_counts_per_IP[ip] = nxdomain_count
        print("NXDOMAIN per IP ", nxdomains_counts_per_IP)



    def analyzer(self):
        while self.active:
            print("LOOP OF ANALYZER !!!")
            self.analyze_NXDOMAIN()
            time.sleep(self.iteration_time)

    def safe_run_analyzer(self):
        safe_run(self.analyzer)