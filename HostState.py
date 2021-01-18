import threading
import logging
import scapy.all as sc

from ARP_spoofer import ARP_spoofer
from Sniffer import Sniffer
from PacketParser import PacketParser

from config import IP_VICTIMS, BLACKLIST_DOMAINS


class HostState:
    """Host state that starts all threads and stores the global information"""
    def __init__(self):
        self.host_ip = None
        self.host_mac = None
        self.gateway_ip = None
        self.victim_ip_list = []
        self.interface = None
        self.lock = threading.Lock()
        # ARP table that will be modified on the go
        self.arp_table = {}
        # pDNS table: keys are domains, values are lists of IPs
        self.passive_DNS = {}

        self.ARP_spoof_thread = None
        self.sniffer_thread = None
        self.packet_parser = None

        self.blacklist_domains = BLACKLIST_DOMAINS

    def start(self):
        # TODO: watch for IP changes in the network
        logging.info("[Host] Getting connection parameters")
        self.interface, self.host_ip, self.gateway_ip = sc.conf.route.route("0.0.0.0")
        self.host_mac = sc.get_if_hwaddr(self.interface)
        self.victim_ip_list = IP_VICTIMS
        self.packet_parser = PacketParser(self)

        self.ARP_spoof_thread = ARP_spoofer(self)
        self.ARP_spoof_thread.victim_ip_list = self.victim_ip_list
        self.ARP_spoof_thread.start()

        self.sniffer_thread = Sniffer(self)
        self.sniffer_thread.start()


    def stop(self):
        self.ARP_spoof_thread.stop()
        self.sniffer_thread.stop()
        with self.lock:
            print("PASSIVE DNS:")
            print(self.passive_DNS)

    def get_arp_table(self):
        with self.lock:
            # return a copy of the arp_table
            return dict(self.arp_table)

    def set_arp_table(self, ip, mac):
        """adds or edits the arp table to add the mapping ip -> mac"""
        with self.lock:
            self.arp_table[ip] = mac
