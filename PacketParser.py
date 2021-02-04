import logging
import scapy.all as sc

from utils_variables import DNS_RECORD_TYPE
from utils import safe_run

class PacketParser:
    def __init__(self, host_state):
        self._host_state = host_state
        self._victim_list = self._host_state.victim_ip_list
        self.socket = sc.conf.L2socket()
        self.blacklist = self._host_state.blacklist_domains

    def add_to_pDNS(self, domain_name, response_list):
        """Add entry to pDNS database in the host_state. Note that not all IPs are actually used because of DNS spoofing"""
        with self._host_state.lock:
            if domain_name not in self._host_state.passive_DNS:
                self._host_state.passive_DNS[domain_name] = response_list
            else:
                for ip in response_list:
                    if ip not in self._host_state.passive_DNS[domain_name]:
                        self._host_state.passive_DNS[domain_name].append(ip)


    def is_in_blacklist(self, domain):
        """
        Returns True if the fully qualified domain is in the blacklist
        Note that the blacklist can be used as wilcards: \"facebook.com\" can block \"analytics.facebook.com\n
        """
        for black_domain in self.blacklist:
            # get the level of the blacklisted domain, and extract same level out of given domain
            black_domain_level = black_domain.count(".") + 1
            domain_same_level = ".".join(domain.split(".")[-black_domain_level:])
            if domain_same_level == black_domain:
                logging.info("[Packet Parser] Domain %s is blacklisted by rule: %s", domain, black_domain)
                return True
        return False


    def forward_packet(self, pkt):
        """Forwards packets in the ARP spoofing"""
        # reference for forwarding: https://stackoverflow.com/questions/61857033/scapy-how-to-forward-packets-after-using-arpspoof
        src_mac = pkt[sc.Ether].src
        dst_mac = pkt[sc.Ether].dst
        src_ip = pkt[sc.IP].src
        dst_ip = pkt[sc.IP].dst

        # grab current ARP table
        arp_table = {}
        while len(arp_table) < 2:
            with self._host_state.lock:
                arp_table = self._host_state.arp_table.copy()
        
        if dst_mac == self._host_state.host_mac and src_ip in self._victim_list:
            # Target --> Local ==> Local --> Gateway
            # logging.debug("Forwarding packet to gateway")
            pkt[sc.Ether].src = self._host_state.host_mac.lower()
            pkt[sc.Ether].dst = arp_table[self._host_state.gateway_ip]
            self.socket.send(pkt)

        elif dst_mac == self._host_state.host_mac and dst_ip in self._victim_list:
            # Gateway --> Local ==> Local --> Target
            # logging.debug("Forwarding packet to victim")
            if src_mac != arp_table[self._host_state.gateway_ip]:
                logging.error("[Packet Parser] Packet to victim going through host but not from gateway ?")
            pkt[sc.Ether].src = self._host_state.host_mac.lower()
            pkt[sc.Ether].dst = arp_table[dst_ip].lower()
            self.socket.send(pkt)

        else:
            # not a packet to forward
            return
            # if (src_ip == self._host_state.gateway_ip and dst_ip not in self._host_state.victim_ip_list) or (src_ip not in self._host_state.victim_ip_list and dst_ip == self._host_state.gateway_ip):
            #     if src_ip not in self._host_state.victim_ip_list:
            #         logging.debug("[Packet Parser] Packet from a not spoofed device: %s", src_ip)
            #     elif dst_ip not in self._host_state.victim_ip_list:
            #         logging.debug("[Packet Parser] Packet to a not spoofed device: %s", dst_ip)
            # else: logging.debug("Neither to victim or to gateway: MAC: %s -> %s, IP: %s -> %s, victim list %s", src_mac, dst_mac, src_ip, dst_ip, self._victim_list)


    def parse_DNS_response(self, pkt):
        """parse DNS packets to extract sld and IP list"""
        domain_name = pkt[sc.DNS].qd.qname.decode().rstrip(".")
        response_list = []
        for x in range(pkt[sc.DNS].ancount):
            # filter to find A record
            answer = pkt[sc.DNS].an[x]
            if answer.type in DNS_RECORD_TYPE:
                dns_type = DNS_RECORD_TYPE[answer.type]
                if dns_type == "A" or dns_type == "AAAA":
                    response = pkt[sc.DNS].an[x].rdata
                    response_list.append(response)
        return domain_name, response_list


    def spoof_DNS(self, pkt):
        """Takes a DNS response and spoof it if it is a blacklisted domain, replaces DNS response with our host IP to prevent packets from reaching the domain"""
        host_ip = self._host_state.host_ip
        redirect_to = host_ip
        domain = pkt[sc.DNSRR].rrname.decode("utf-8").rstrip(".")

        spoofed_response = sc.IP(dst=pkt[sc.IP].dst, src=pkt[sc.IP].src)/\
                            sc.UDP(dport=pkt[sc.UDP].dport, sport=pkt[sc.UDP].sport)/\
                            sc.DNS(id=pkt[sc.DNS].id, qd=pkt[sc.DNS].qd, aa = 1, qr=1, \
                                an=sc.DNSRR(rrname=domain,  ttl=600, rdata=redirect_to))
        logging.info("[Packet Parser] Spoofing %s to IP %s", domain, redirect_to)
        sc.send(spoofed_response, verbose=False)


    def parse_packet(self, pkt):
        try:
            if pkt[sc.Ether].src == self._host_state.host_mac:
                # do not parse outcoming packets
                return

            # only deal with IP packets, which are targetted by ARP spoofing
            if sc.IP in pkt:
                if pkt[sc.IP].dst == self._host_state.host_ip:
                    #do not parse packets destined to our host
                    return 

                has_DNS_layer = (sc.DNS in pkt)
                if has_DNS_layer:
                    is_DNS_query = (pkt[sc.DNS].qr == 0)
                    if is_DNS_query:
                        # forward DNS queries
                        self.forward_packet(pkt)
                    else:
                        # check that response is not empty
                        if pkt[sc.DNS].qdcount > 0 and pkt[sc.DNS].ancount > 0 and pkt.haslayer(sc.DNSRR):
                            # parse DNS response
                            fqdn, ip_list = self.parse_DNS_response(pkt)
                            logging.info("[PacketParser] Domain %s, ip list %s", fqdn, ip_list)
                            # add to pDNS data
                            self.add_to_pDNS(fqdn, ip_list)
                            if self.is_in_blacklist(fqdn):
                                self.spoof_DNS(pkt)
                            else:
                                self.forward_packet(pkt)

                else: # has no DNS layer,
                    # checking for blacklist is not necessary since DNS is spoofed
                    # TODO: sent pkt to traffic monitor
                    # forward packet since packet is ARP spoofed
                    self.forward_packet(pkt)
        except OSError:
            # some packets are too big to be sent to sockets, causing OSError, to fix.
            pass


    def prn_call(self, pkt):
        """This is the function that is called by the prn callback in Sniffer"""
        safe_run(self.parse_packet, args=[pkt])
