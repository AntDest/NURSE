import threading
import logging
import time
import socket
from src.utils.utils import merge_dict, FlowKey, FlowPkt
from src.Classifier import DomainClassifier
from src.utils.utils import get_mac, get_device_name, get_vendor_from_mac


class TrafficMonitor:
    """
    This class implements the traffic monitor
    It receives data from the packet parser and keeps track of traffic features by updating its local data
    """
    def __init__(self, host_state, update_delay):
        self.host_state = host_state
        
        self.updater_thread = threading.Thread(target=self.updater)
        self.lock = threading.Lock()
        self.active = True
        self.update_delay = update_delay
        self.active_check_interval = 5

        self.device_names = {}      # MAC -> name
        self.queried_domains = {}
        self.blocked_domains = set()
        self.passive_DNS = {}
        self.arp_table = {}
        self.flows = {}
        self.domain_scores = {}

        logging.info("[TrafficMonitor] Initialising classifier")
        self.classifier = DomainClassifier()

    def start(self):
        with self.lock:
            self.active = True
        logging.info("[Monitor] Traffic monitor starting")
        # copy the ARP table of the host state, which has some info?
        self.updater_thread.start()

    def stop(self):
        logging.info("[Monitor] Traffic monitor stopping")
        self.active = False
        self.classifier.delete_file()
        self.updater_thread.join()


    def new_device(self, ip):
        """Gathers info and adds the device to ARP table and device names"""
        # obtain mac of IP
        if ip not in self.arp_table:
            mac = get_mac(ip)
            self.arp_table[ip] = mac
        else:
            mac = self.arp_table[ip]
        
        #obtain device name
        if mac not in self.device_names:
            name = get_device_name(ip)
            manufacturer = get_vendor_from_mac(mac)
            self.device_names[mac] = (name, manufacturer)


    def updater(self):
        while self.active:
            for ip in self.arp_table:
                self.new_device(ip)
                
            logging.info("[Monitor] Updating data to host thread")
            with self.host_state.lock:
                # update passive DNS: for each domain add the new IPs (the IP list is a set)
                for domain in self.passive_DNS:
                    self.host_state.passive_DNS.setdefault(domain, set()).update(self.passive_DNS[domain])

                # update queried domains
                self.host_state.queried_domains = self.queried_domains.copy()

                # update ARP table
                new_ARP = merge_dict(self.host_state.arp_table, self.arp_table)
                self.host_state.arp_table = new_ARP.copy()

                #update device names
                self.host_state.device_names = self.device_names.copy()

                #update the list of blocked domains
                self.host_state.blocked_domains.update(self.blocked_domains)

                # update the list of flows
                for flow_key in self.flows:
                    if flow_key not in self.host_state.flows:
                        self.host_state.flows[flow_key] = [] 
                    self.host_state.flows[flow_key] += self.flows[flow_key]

                self.host_state.domain_scores = self.domain_scores
                self.host_state.last_update = time.time()
                
            # end of lock
            # wait until next iteration,
            # split waiting time into small waits to check if process is still active
            for seconds_waited in range(0, self.update_delay, self.active_check_interval):
                if not self.active:
                    # break from this waiting loop
                    break
                if (self.update_delay - seconds_waited) > self.active_check_interval:
                    # wait for the check interval duration
                    time.sleep(self.active_check_interval)
                else:
                    # if the check interval is longer than the wait until the next update
                    # only wait until the next update
                    time.sleep((self.update_delay - seconds_waited))


    def score_domain(self, domain):
        X = self.classifier.compute_features(domain)
        # score is computed from proba of being malicious (ie class = 1)
        score = 10 * self.classifier.classifier.predict_proba(X)[0][1]
        return score


    def add_to_pDNS(self, domain_name, ip_list):
        """Called by the packet_parser when a new domain appears in a DNS response
        Adds the domain to the pDNS database (note that the responses may be spoofed, so some IPs will not be contacted)
        """
        # add to pDNS database in host_state
        if domain_name not in self.passive_DNS:
            self.passive_DNS[domain_name] = set(ip_list)
            # new domain: compute its score
            score = self.score_domain(domain_name)
            self.domain_scores[domain_name] = score
        else:
            self.passive_DNS[domain_name].update(ip_list)

    def add_to_queried_domains(self, ip, fqdn, timestamp):
        self.queried_domains.setdefault(ip, []).append((timestamp, fqdn))



    def add_to_blocked_domains(self, domain_name):
        """adds a domain to the list of domains that have been spoofed"""
        if domain_name not in self.blocked_domains:
            self.blocked_domains.add(domain_name)

    def add_to_ARP_table(self, ip, mac):
        """adds an entry to the ARP table of the host state"""
        self.arp_table[ip] = mac

    def add_to_flow(self, flow_key:FlowKey, pkt_att:FlowPkt):
        """Adds an entry to flow based on information received from the packet parser"""
        self.flows.setdefault(flow_key, []).append(pkt_att)