import logging
import threading
import time
import scapy.all as sc
from src.utils.utils import get_device_name

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
        # Contacted domains: keys are IPs, values are list of queried domains (in DNS)
        self.queried_domains = {}
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
        print("Queried domains: ", self.queried_domains)


    def add_to_victim_list(self, ip):
        if ip not in self.victim_ip_list:
            self.victim_ip_list.append(ip)
    
    def remove_from_victim_list(self, ip):
        if ip in self.victim_ip_list:
            self.victim_ip_list.remove(ip)
            self.ARP_spoof_thread.arp_restore_victim(ip)

    def add_device_name(self, ip):
        mac = self.arp_table[ip]
        if mac not in self.device_names:
            self.device_names[mac] = get_device_name(ip)


    def get_arp_table(self):
        with self.lock:
            # return a copy of the arp_table
            return dict(self.arp_table)

    def set_arp_table(self, ip, mac):
        """adds or edits the arp table to add the mapping ip -> mac"""
        with self.lock:
            self.arp_table[ip] = mac
        self.add_device_name(ip)


    def get_device_list(self):
        """
        Returns a list of dicts with MAC, IP, name and a boolean which indicates if device is spoofed 
        If a device has no name, the name is \"\"
        """
        print("ON REQUEST")
        print(self.device_names)
        print(self.arp_table)
        devices = []
        for device_id, ip in enumerate(self.arp_table):
            d = {}
            mac = self.arp_table[ip]
            d["id"] = device_id
            d["IP"] = ip
            d["MAC"] = mac
            if mac in self.device_names:
                name = self.device_names[mac]
            else:
                name = ""
            d["name"] = name
            d["victim"] = (ip in self.victim_ip_list)
            devices.append(d)
        return devices