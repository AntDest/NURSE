import threading
import logging
import time
from src.utils.utils import merge_dict, FlowKey, FlowPkt
from src.Classifier import DomainClassifier
from src.utils.utils import get_mac, get_device_name, get_vendor_from_mac, disable_if_offline
from src.utils.utils import StopProgramException, restart_on_error
import config

class TrafficMonitor:
    """
    This class implements the traffic monitor
    It receives data from the packet parser and keeps track of traffic features by updating its local data
    """
    def __init__(self, host_state, update_delay):
        self.host_state = host_state
        self.updater_thread = threading.Thread(target=self.safe_updater)
        self.lock = threading.Lock()
        self.active = True
        self.update_delay = update_delay

        self.device_names = {}      # MAC -> name
        self.queried_domains = {}
        self.blocked_domains = set()
        self.passive_DNS = {}
        self.arp_table = {}
        self.flows = {}
        self.domain_scores = {}

        self.classifier = None
        self.last_timestamp = 0
        self.new_data = False #turns to true, if new data comes

    def start(self):
        if self.classifier is None:
            logging.info("[TrafficMonitor] Initialising classifier")
            self.classifier = DomainClassifier()
        with self.lock:
            self.active = True

        logging.info("[Monitor] Traffic monitor starting")
        self.updater_thread.start()

    def stop(self):
        logging.info("[Monitor] Traffic monitor stopping")
        self.active = False
        self.classifier.delete_file()
        self.updater_thread.join()


    def new_device_get_mac(self, ip, mac=""):
        # obtain mac of IP
        if ip not in self.arp_table:
            if mac == "":
                mac = get_mac(ip)
            if mac is None or mac == "":
                # return and do not add this empty mac to the ARP table
                return ""
            self.arp_table[ip] = mac
        else:
            mac = self.arp_table[ip]
        return mac

    def new_device_get_name(self, ip, mac):
        #obtain device name
        if mac != "" and mac not in self.device_names:
            if self.host_state.online:
                name = get_device_name(ip)
            else:
                name = "-"
            manufacturer = get_vendor_from_mac(mac)
            self.device_names[mac] = (name, manufacturer)


    # active discovery function, so disabled when offline
    def new_device(self, ip, mac=""):
        """Gathers info and adds the device to ARP table and device names"""
        if ip != "0.0.0.0":
            mac = self.new_device_get_mac(ip, mac)
            self.new_device_get_name(ip, mac)
            self.new_data = True
            if not self.host_state.online:
                self.host_state.add_to_victim_list(ip)



    def sleep(self, seconds):
        """Sleep for given seconds, but check if still active every second"""
        for _ in range(seconds):
            if not self.active:
                break
            time.sleep(1)


    def updater(self):
        while self.active:
            if self.new_data:
                for ip in self.arp_table.copy():
                    self.new_device(ip)

                # logging.debug("[Monitor] Updating data to host thread")
                with self.host_state.lock:
                    # update passive DNS: for each domain add the new IPs (the IP list is a set)
                    for domain in self.passive_DNS:
                        self.host_state.passive_DNS.setdefault(domain, set()).update(self.passive_DNS[domain])

                    # update queried domains
                    # do not use copy(), simply add the new data
                    for ip in self.queried_domains.copy():
                        new_tuples = []
                        for t in reversed(self.queried_domains[ip]):
                            if t not in self.host_state.queried_domains:
                                new_tuples.append(t)
                            else:
                                break
                        # reverse data to keep chronological order in queried domains
                        new_data = new_tuples[::-1]
                        if ip not in self.host_state.queried_domains:
                            self.host_state.queried_domains[ip] = new_data
                        else:
                            self.host_state.queried_domains[ip] += new_data

                    # update ARP table
                    new_ARP = merge_dict(self.host_state.arp_table, self.arp_table)
                    self.host_state.arp_table = new_ARP.copy()

                    #update device names
                    self.host_state.device_names = self.device_names.copy()

                    #update the list of blocked domains
                    self.host_state.blocked_domains.update(self.blocked_domains)

                    # update the list of flows
                    for flow_key in self.flows.copy():
                        if flow_key not in self.host_state.flows:
                            self.host_state.flows[flow_key] = []
                        self.host_state.flows[flow_key] += self.flows[flow_key]

                    self.host_state.domain_scores = self.domain_scores
                    self.host_state.last_update = time.time()
                    self.host_state.last_timestamp = self.last_timestamp
                    self.new_data = False
                # end of lock
                # wait until next iteration,
                # split waiting time into small waits to check if process is still active
            else:
                logging.info("[Monitor] No new data")
                print("offline: {}, timestamp is {} and last update is {}. Difference={} and STOP_AFTER is {}".format(not self.host_state.online, int(time.time()), self.host_state.last_update, time.time() - self.host_state.last_update, config.STOP_AFTER_WITH_NO_INFO))
                if not self.host_state.online and time.time() - self.host_state.last_update > config.STOP_AFTER_WITH_NO_INFO:
                    print("[TrafficMonitor] ===== Stopping because no data has been received since {}s".format(config.STOP_AFTER_WITH_NO_INFO))
                    self.host_state.active = False
            self.sleep(self.update_delay)


    def safe_updater(self):
        restart_on_error(self.updater)


    def score_domain(self, domain):
        X = self.classifier.compute_features(domain)
        # score is computed from proba of being malicious (ie class = 1)
        score = 10 * self.classifier.classifier.predict_proba(X)[0][1]
        return score


    def add_to_pDNS(self, domain_name, ip_list):
        """Called by the packet_parser when a new domain appears in a DNS response
        Adds the domain to the pDNS database (note that the responses may be spoofed, so some IPs will not be contacted)
        """
        # add to pDNS database
        if domain_name not in self.passive_DNS:
            self.passive_DNS[domain_name] = set(ip_list)
            # new domain: compute its score
            score = self.score_domain(domain_name)
            self.domain_scores[domain_name] = round(score,2)
        else:
            self.passive_DNS[domain_name].update(ip_list)
            self.new_data = True

    def add_to_queried_domains(self, ip, fqdn, timestamp):
        self.queried_domains.setdefault(ip, []).append((timestamp, fqdn))
        self.last_timestamp = timestamp
        self.new_data = True


    def add_to_blocked_domains(self, domain_name):
        """adds a domain to the list of domains that have been spoofed"""
        if domain_name not in self.blocked_domains:
            self.blocked_domains.add(domain_name)
        self.new_data = True

    def add_to_ARP_table(self, ip, mac):
        """adds an entry to the ARP table of the host state"""
        if ip != "0.0.0.0":
            self.arp_table[ip] = mac
            self.new_device_get_name(ip, mac)
            self.new_data = True

    def add_to_flow(self, flow_key:FlowKey, pkt_att:FlowPkt):
        """Adds an entry to flow based on information received from the packet parser"""
        self.flows.setdefault(flow_key, []).append(pkt_att)
        self.last_timestamp = pkt_att.timestamp
        self.new_data = True