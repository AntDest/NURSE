import threading
import logging
import time
from src.utils import merge_dict, FlowKey, FlowPkt


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

        self.blocked_domains = set()
        self.passive_DNS = {}
        self.arp_table = {}
        self.flows = {}

    def start(self):
        with self.lock:
            self.active = True
        logging.info("[Server] Server starting")
        self.updater_thread.start()

    def stop(self):
        logging.info("[Monitor] Monitor stopping")
        self.active = False
        self.updater_thread.join()




    def updater(self):
        while self.active:
            logging.info("[Monitor] Updating data to host thread")
            with self.host_state.lock:
                # update passive DNS: for each domain add the new IPs (the IP list is a set)
                for domain in self.host_state.traffic_monitor.passive_DNS:
                    self.host_state.passive_DNS.setdefault(domain, set()).update(self.host_state.traffic_monitor.passive_DNS[domain])

                # update ARP table
                new_ARP = merge_dict(self.host_state.arp_table, self.host_state.traffic_monitor.arp_table)
                self.host_state.arp_table = new_ARP.copy()

                #update the list of blocked domains
                self.host_state.blocked_domains.update(self.host_state.traffic_monitor.blocked_domains)

                # update the list of flows
                for flow_key in self.flows:
                    if flow_key not in self.host_state.flows:
                        self.host_state.flows[flow_key] = [] 
                    self.host_state.flows[flow_key] += self.flows[flow_key]

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




    def add_to_pDNS(self, domain_name, ip_list):
        """Called by the packet_parser when a new domain appears in a DNS response
        Adds the domain to the pDNS database (note that the responses may be spoofed, so some IPs will not be contacted)
        """
        # add to pDNS database in host_state
        if domain_name not in self.passive_DNS:
            self.passive_DNS[domain_name] = set(ip_list)
        else:
            self.passive_DNS[domain_name].update(ip_list)

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