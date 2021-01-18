import scapy.all as sc
import logging
import traceback


DNS_RECORD_TYPE = {
    1: "A",
    28: "AAAA",
    # 2: "NS", 5: "CNAME", 12: "PTR", 33: "SRV", 16: "TXT", 43: "DS", 48: "DNSKEY", 13: "HINFO"
}

class PacketParser:
    def __init__(self, host_state):
        self._host_state = host_state
        self._victim_list = self._host_state.victim_ip_list
        self.socket = sc.conf.L2socket()
        self.blacklist = self._host_state.blacklist_domains
        self.pDNS = {}

# DNS spoofing
    def parse_DNS(self, pkt):
        """parse DNS packets to extract sld and IP list"""
        domain_name = pkt[sc.DNS].qd.qname.decode().rstrip(".")
        sld = ".".join(domain_name.split(".")[-2:])
        # only using sld instead of FQDN, to prevent www.site.com from loading when site.com is banned
        response_list = []
        for x in range(pkt[sc.DNS].ancount):
            # filter to find A record
            answer = pkt[sc.DNS].an[x]
            if answer.type in DNS_RECORD_TYPE:
                dns_type = DNS_RECORD_TYPE[answer.type]
                if dns_type == "A" or dns_type == "AAAA":
                    response = pkt[sc.DNS].an[x].rdata
                    response_list.append(response)
        return sld, response_list

    def DNS_spoofer(self, pkt):
        """Takes a DNS response and spoof it if it is a blacklisted domain, replaces DNS response with our host IP to prevent packets from reaching the domain"""
        host_ip = self._host_state.host_ip
        redirect_to = host_ip
        if pkt.haslayer(sc.DNSRR): # DNS question record
            domain = pkt[sc.DNSRR].rrname.decode("utf-8").rstrip(".")
            sld = ".".join(domain.split(".")[-2:])
            if domain in self.blacklist or sld in self.blacklist:
                spoofed_response = sc.IP(dst=pkt[sc.IP].dst, src=pkt[sc.IP].src)/\
                            sc.UDP(dport=pkt[sc.UDP].dport, sport=pkt[sc.UDP].sport)/\
                            sc.DNS(id=pkt[sc.DNS].id, qd=pkt[sc.DNS].qd, aa = 1, qr=1, \
                            an=sc.DNSRR(rrname=domain,  ttl=600, rdata=redirect_to))
                logging.info("[Packet Parser] Spoofing %s to IP %s", domain, redirect_to)
                sc.send(spoofed_response, verbose=False)
                return True
        return False

# forwarding for ARP spoofing
    def check_filter_packet(self, pkt):
        """Returns False if packet has to be filtered out, true if the packet can be forwarded"""
        # useless now that filtering is based on DNS spoofing
        if sc.IP in pkt:
            dst_ip = pkt[sc.IP].dst
            blacklisted_IPs = self.get_IP_blacklist()
            if dst_ip in blacklisted_IPs:
                domain = self.IP_to_domain(dst_ip)
                logging.warning("Blocking traffic meant to %s", domain)
                return False
        return True

    def forward_packet(self, pkt):
        """Forwards packets in the ARP spoofing"""
        # do not parse outcoming packet:
        if pkt[sc.Ether].src == self._host_state.host_mac:
            return None

        # now only incoming packets are parsed
        if sc.IP in pkt:
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
                if (src_ip == self._host_state.gateway_ip and dst_ip not in self._host_state.victim_ip_list) or (src_ip not in self._host_state.victim_ip_list and dst_ip == self._host_state.gateway_ip):
                    if src_ip not in self._host_state.victim_ip_list:
                        logging.debug("[Packet Parser] Packet from a not spoofed device: %s", src_ip)
                    elif dst_ip not in self._host_state.victim_ip_list:
                        logging.debug("[Packet Parser] Packet to a not spoofed device: %s", dst_ip)
                # else: logging.debug("Neither to victim or to gateway: MAC: %s -> %s, IP: %s -> %s, victim list %s", src_mac, dst_mac, src_ip, dst_ip, self._victim_list)


# data extraction to host state and monitoring
    def add_to_pDNS(self, domain_name, response_list):
        """Add entry to pDNS database in the host_state. Note that not all IPs are actually used because of DNS spoofing"""
        with self._host_state.lock:
            if domain_name not in self._host_state.passive_DNS:
                self._host_state.passive_DNS[domain_name] = response_list
            else:
                for ip in response_list:
                    if ip not in self._host_state.passive_DNS[domain_name]:
                        self._host_state.passive_DNS[domain_name].append(ip)

    def get_IP_blacklist(self):
        """converts the blacklist of domains into a list of banned IPs, based on the pDNS database"""
        blacklisted_IPs = []
        with self._host_state.lock:
            self.pDNS = self._host_state.passive_DNS
        for black_domain in self.blacklist:
            if black_domain in self.pDNS:
                blacklisted_IPs += self.pDNS[black_domain]
        return blacklisted_IPs

    def IP_to_domain(self, ip):
        for domain in self.pDNS:
            if ip in self.pDNS[domain]:
                return domain
        return None

    def extract_data_for_monitor(self, pkt):
        pass


#main function, called by scapy.sniff prn argument
    def parse_packet(self, pkt):
        """Called in the sniff of the Sniffer. Calls DNS parser and spoofer, forwards the packet if ARP spoofed"""
        try:
            if pkt[sc.Ether].src == self._host_state.host_mac:
                # do not parse outcoming packets
                return
            else:
                # only deal with IP packets, which are targetted by ARP spoofing
                if sc.IP in pkt:
                    if pkt[sc.IP].dst == self._host_state.host_ip:
                        #do not parse packets destined to our host
                        return
                    if sc.DNS in pkt:
                        if pkt[sc.DNS].qr == 1:
                            spoofed = False
                            if pkt[sc.DNS].qdcount > 0 and pkt[sc.DNS].ancount > 0:
                                # DNS Response, parse it and update pDNS in host state
                                domain_name, response_list = self.parse_DNS(pkt)
                                self.add_to_pDNS(domain_name, response_list)
                                # send the DNS response to the spoofer, which will forward the packet or send a spoofed response if necessary
                                spoofed = self.DNS_spoofer(pkt)
                                # forward any DNS packet that has not been spoofed
                            if not spoofed:
                                self.forward_packet(pkt)
                        elif pkt[sc.DNS].qr == 0:
                            #forward all the DNS queries
                            self.forward_packet(pkt)
                    else:
                        # if not DNS, forward the packet, unless it is a blacklisted domain
                        if self.check_filter_packet(pkt):
                            # check_filter_packet checks whether the destination IP is in the blacklist.
                            # But this should never happen since DNS is spoofed
                            self.forward_packet(pkt)
        except OSError:
            # some packets are too big to be sent to sockets, causing OSError, to fix.
            pass
        except Exception as e:
            pkt.show()
            logging.debug(traceback.format_exc())
            logging.debug(pkt.summary())
            logging.error(e)