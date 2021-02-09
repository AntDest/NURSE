import logging
import scapy.all as sc

from src.utils_variables import DNS_RECORD_TYPE
from src.utils import safe_run, FlowKey, FlowPkt
from src.TrafficMonitor import TrafficMonitor

class PacketParser:
    def __init__(self, host_state, traffic_monitor):
        self._host_state = host_state
        self.traffic_monitor = traffic_monitor
        self._victim_list = self._host_state.victim_ip_list
        self.socket = sc.conf.L2socket()
        self.blacklist = self._host_state.blacklist_domains

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



    def parse_DNS(self, pkt):
        is_DNS_query = (pkt[sc.DNS].qr == 0)
        if is_DNS_query:
            # forward DNS queries
            self.forward_packet(pkt)
        else:
            # check that response is not empty
            if pkt[sc.DNS].qdcount > 0 and pkt[sc.DNS].ancount > 0 and pkt.haslayer(sc.DNSRR):
                # parse DNS response
                fqdn, ip_list = self.parse_DNS_response(pkt)
                logging.debug("[Packet Parser] Domain %s, ip list %s", fqdn, ip_list)
                # add to pDNS data
                self.traffic_monitor.add_to_pDNS(fqdn, ip_list)
                if self.is_in_blacklist(fqdn):
                    self.spoof_DNS(pkt)
                    self.traffic_monitor.add_to_blocked_domains(fqdn)
                else:
                    self.forward_packet(pkt)
            else:
                #there was no response record
                if pkt[sc.DNS].rcode == 3:
                    #NXDOMAIN
                    fqdn = pkt[sc.DNS].qd.qname.decode().rstrip(".")
                    logging.debug("[Packet Parser] Domain %s does not exist", fqdn)
                    self.traffic_monitor.add_to_pDNS(fqdn, [])
                    self.forward_packet(pkt)


    def parse_ARP(self, pkt):
        """Process an ARP packet and update the ARP table of the host state"""
        if pkt.op == 2:
            # only deal with ARP responses
            mac =  pkt[sc.ARP].hwsrc
            ip = pkt[sc.ARP].psrc
            self.traffic_monitor.add_to_ARP_table(ip, mac)

    
    def parse_TCP_UDP(self, pkt, protocol):
        """
        Parse a TCP packet to extract information and send it to the traffic monitor
        protocol should be \"TCP\" or \"UDP\"
        """
        if protocol == "TCP": 
            proto = sc.TCP
        elif protocol == "UDP": 
            proto = sc.UDP
        else:
            raise Exception(f"Unknown protocol {protocol}")
        #determine if packet is outbound or inboud:
        if pkt[sc.IP].src in self._victim_list:
            ip_src = pkt[sc.IP].src
            ip_dst = pkt[sc.IP].dst
            port_src = pkt[proto].sport
            port_dst = pkt[proto].dport
            inbound = False     # inbound means out to in 
        elif pkt[sc.IP].dst in self._victim_list:
            ip_src = pkt[sc.IP].dst
            ip_dst = pkt[sc.IP].src
            port_dst = pkt[proto].sport
            port_src = pkt[proto].dport
            inbound = True

        flow_key = FlowKey(
            IP_src=ip_src,
            IP_dst=ip_dst,
            port_src=port_src,
            port_dst=port_dst,
            protocol=protocol
        )
        pkt_attributes = FlowPkt(
            inbound=inbound,
            size=len(pkt[proto].payload),
            timestamp=pkt.time
        )
        self.traffic_monitor.add_to_flow(flow_key, pkt_attributes)
        


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
                elif pkt[sc.IP].dst not in self._victim_list and pkt[sc.IP].src not in self._victim_list:
                    # packet from IPs that are not victims
                    return
                if sc.DNS in pkt:
                    self.parse_DNS(pkt)
                    # do not forward packet here, since it may be spoofed
                elif sc.ARP in pkt:
                    self.parse_ARP(pkt)
                    self.forward_packet(pkt)
                elif sc.TCP in pkt:
                    self.parse_TCP_UDP(pkt, protocol="TCP")
                    self.forward_packet(pkt)
                elif sc.UDP in pkt:
                    self.parse_TCP_UDP(pkt, protocol="UDP")
                    self.forward_packet(pkt)
                else: # has no known layer
                    # checking for blacklist should not be necessary since DNS is spoofed
                    # forward packet since the packet destination MAC is spoofed
                    self.forward_packet(pkt)
        except OSError:
            # some packets are too big to be sent to sockets, causing OSError, to fix.
            pass


    def prn_call(self, pkt):
        """This is the function that is called by the prn callback in Sniffer"""
        safe_run(self.parse_packet, args=[pkt])
