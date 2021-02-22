import logging
import threading
import time
import scapy.all as sc

class HostState:
    """Host state that starts all threads and stores the global information"""
    def __init__(self):
        self.lock = threading.Lock()

        # list of network parameters that will be useful for child threads
        self.host_ip = None
        self.host_mac = None
        self.gateway_ip = None
        self.victim_ip_list = []
        self.interface = None

        # all children threads
        self.ARP_spoof_thread = None
        self.sniffer_thread = None
        self.packet_parser = None
        self.traffic_monitor = None
        self.server_thread = None


        # global data storage about traffic
        # ARP table that will be modified on the go
        self.arp_table = {}
        # pDNS table: keys are domains, values are lists of IPs
        self.passive_DNS = {}
        # list of all fqdn that have been spoofed
        self.blocked_domains = set()
        #dict of all flows
        # keys are namedtuples (IP_src, IP_dst, port_src, port_dst, protocol)
        # by convention, IP_src is the victim IP
        # protocol is UDP or TCP
        self.flows = {}
        # dict containing scores from the classifier for each domain
        self.domain_scores = {}
        # dict dontaining device names: mac -> device_names
        self.device_names = {}
        self.last_update = time.time()

    def start(self):
        # TODO: watch for IP changes in the network
        logging.info("[Host] Getting connection parameters")
        self.interface, self.host_ip, self.gateway_ip = sc.conf.route.route("0.0.0.0")
        self.host_mac = sc.get_if_hwaddr(self.interface)


        self.ARP_spoof_thread.victim_ip_list = self.victim_ip_list
        self.ARP_spoof_thread.start()
        self.traffic_monitor.start()
        self.sniffer_thread.start()
        self.server_thread.start()


    def stop(self):
        self.ARP_spoof_thread.stop()
        self.sniffer_thread.stop()
        self.traffic_monitor.stop()
        print("Blocked domains: ", self.blocked_domains)
        print("Domain scores: ", self.domain_scores)
        print("Devices: ", self.device_names)


    def get_arp_table(self):
        with self.lock:
            # return a copy of the arp_table
            return dict(self.arp_table)

    def set_arp_table(self, ip, mac):
        """adds or edits the arp table to add the mapping ip -> mac"""
        with self.lock:
            self.arp_table[ip] = mac
