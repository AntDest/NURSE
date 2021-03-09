import logging
import threading
import time
import requests
import scapy.all as sc
from config import CHECK_IP_URL_LIST

class HostState:
    """Host state that starts all threads and stores the global information"""
    def __init__(self, online):
        self.lock = threading.Lock()
        self.online = online

        # list of network parameters that will be useful for child threads
        self.host_ip = None
        self.host_mac = None
        self.gateway_ip = None
        self.external_ip = None
        self.victim_ip_list = []
        self.interface = None

        # all children threads
        self.ARP_spoof_thread = None
        self.sniffer_thread = None
        self.packet_parser = None
        self.traffic_monitor = None
        self.server_thread = None
        self.alert_manager = None
        self.traffic_analyzer = None

        # global data storage about traffic
        # ARP table that will be modified on the go
        self.arp_table = {}
        # pDNS table: keys are domains, values are lists of IPs
        self.passive_DNS = {}
        # Contacted domains: keys are IPs, values are list of tuples (timestamp, queried domains (in DNS))
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
        # dict dontaining device names: mac -> (device_name, manufacturer)
        self.device_names = {}
        self.last_update = time.time()
        self.last_timestamp = 0     # last timestamp of uploaded data


    def set_capture_file(self, capture_file):
        if not self.online and capture_file != "":
            self.capture_file = capture_file
        else:
            self.capture_file = None
            
    def start(self):
        # TODO: watch for IP changes in the network
        logging.info("[Host] Getting connection parameters")
        if self.online:
            self.interface, self.host_ip, self.gateway_ip = sc.conf.route.route("0.0.0.0")
            self.host_mac = sc.get_if_hwaddr(self.interface)
        self.ARP_spoof_thread.victim_ip_list = self.victim_ip_list
        self.ARP_spoof_thread.start()
        self.traffic_monitor.start()
        self.sniffer_thread.start()
        self.server_thread.start()
        self.traffic_analyzer.start()

        if self.online:
            self.external_ip = self.get_external_ip()
            logging.info("[HostState] Your external IP is: %s", self.external_ip)
        else:
            self.external_ip = ""

    def stop(self):
        self.ARP_spoof_thread.stop()
        self.sniffer_thread.stop()
        self.traffic_monitor.stop()
        self.traffic_analyzer.stop()
        # print("Blocked domains: ", self.blocked_domains)
        # print("Queried domains: ", self.queried_domains)
        # print("Passive DNS: ", self.passive_DNS)
        if len(self.alert_manager.alert_list) > 0:
            print("Alerts: ")
            for a in self.alert_manager.alert_list:
                print(a)

    def get_external_ip(self):
        # query an API for the exernal IP
        external_ip = None
        while external_ip is None:
            for CHECK_IP_URL in CHECK_IP_URL_LIST:
                r = requests.get(CHECK_IP_URL)
                if r.status_code == 200:
                    external_ip = r.text.strip()
                    break
        return external_ip
        


    def add_to_victim_list(self, ip):
        if ip not in self.victim_ip_list:
            self.victim_ip_list.append(ip)
            # TODO: if offline: rescan the file with new victim list
            if not self.online:
                self.sniffer_thread.restart()
    
    def remove_from_victim_list(self, ip):
        if ip in self.victim_ip_list:
            self.victim_ip_list.remove(ip)
            self.ARP_spoof_thread.arp_restore_victim(ip)

    def get_arp_table(self):
        with self.lock:
            # return a copy of the arp_table
            return dict(self.arp_table)

    def set_arp_table(self, ip, mac):
        """adds or edits the arp table to add the mapping ip -> mac"""
        with self.lock:
            self.arp_table[ip] = mac
        self.traffic_monitor.new_device(ip)


    def get_device_list(self):
        """
        Returns a list of dicts with MAC, IP, name and a boolean which indicates if device is spoofed 
        If a device has no name, the name is \"\"
        """
        devices = []
        for device_id, ip in enumerate(self.arp_table):
            d = {}
            mac = self.arp_table[ip]
            d["id"] = device_id
            d["IP"] = ip
            d["MAC"] = mac
            if mac in self.device_names:
                name = self.device_names[mac][0]
                manufacturer = self.device_names[mac][1]
            else:
                name = ""
                manufacturer = ""
            d["name"] = name
            d["manufacturer"] = manufacturer
            d["victim"] = (ip in self.victim_ip_list)
            devices.append(d)
        return devices