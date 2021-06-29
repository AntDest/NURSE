import logging
import scapy.all as sc
import time
import datetime
from src.utils.utils_variables import DNS_RECORD_TYPE
from src.utils.utils import safe_run, FlowKey, FlowPkt, disable_if_offline, IP_is_private
from src.utils.utils import StopProgramException

class PacketParser:
    def __init__(self, host_state, traffic_monitor):
        self.host_state = host_state
        self.traffic_monitor = traffic_monitor
        self._victim_list = self.host_state.victim_ip_list
        self.count = 0
        self.delays = []

    def is_in_blacklist(self, domain):
        """
        Returns True if the fully qualified domain is in the blacklist
        Note that the blacklist can be used as wilcards: \"facebook.com\" can block \"analytics.facebook.com\n
        """
        blacklist = self.host_state.config.get_config("BLACKLIST_DOMAINS")
        for black_domain in blacklist:
            # get the level of the blacklisted domain, and extract same level out of given domain
            black_domain_level = black_domain.count(".") + 1
            domain_same_level = ".".join(domain.split(".")[-black_domain_level:])
            if domain_same_level == black_domain:
                if self.host_state.online:
                    logging.info("[Packet Parser] Domain %s is blacklisted by rule: %s", domain, black_domain)
                return True
        return False

    @disable_if_offline
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
            with self.host_state.lock:
                arp_table = self.host_state.arp_table.copy()

        if dst_mac == self.host_state.host_mac and src_ip in self._victim_list:
            # Target --> Local ==> Local --> Gateway
            # logging.debug("Forwarding packet to gateway")
            pkt[sc.Ether].src = self.host_state.host_mac.lower()
            pkt[sc.Ether].dst = arp_table[self.host_state.gateway_ip]
            sc.sendp(pkt, verbose=False)

        elif dst_mac == self.host_state.host_mac and dst_ip in self._victim_list:
            # Gateway --> Local ==> Local --> Target
            # logging.debug("Forwarding packet to victim")
            if src_mac != arp_table[self.host_state.gateway_ip]:
                logging.error("[Packet Parser] Packet to victim going through host but not from gateway ?")
            pkt[sc.Ether].src = self.host_state.host_mac.lower()
            pkt[sc.Ether].dst = arp_table[dst_ip].lower()
            sc.sendp(pkt, verbose=False)

        else:
            # not a packet to forward
            return
            # if (src_ip == self.host_state.gateway_ip and dst_ip not in self.host_state.victim_ip_list) or (src_ip not in self.host_state.victim_ip_list and dst_ip == self.host_state.gateway_ip):
            #     if src_ip not in self.host_state.victim_ip_list:
            #         logging.debug("[Packet Parser] Packet from a not spoofed device: %s", src_ip)
            #     elif dst_ip not in self.host_state.victim_ip_list:
            #         logging.debug("[Packet Parser] Packet to a not spoofed device: %s", dst_ip)
            # else: logging.debug("Neither to victim or to gateway: MAC: %s -> %s, IP: %s -> %s, victim list %s", src_mac, dst_mac, src_ip, dst_ip, self._victim_list)

    @disable_if_offline
    def spoof_DNS(self, pkt):
        """Takes a DNS response and spoof it if it is a blacklisted domain, replaces DNS response with our host IP to prevent packets from reaching the domain"""
        host_ip = self.host_state.host_ip
        redirect_to = host_ip
        domain = pkt[sc.DNSRR].rrname.decode("utf-8").rstrip(".")

        spoofed_response = sc.IP(dst=pkt[sc.IP].dst, src=pkt[sc.IP].src)/\
                            sc.UDP(dport=pkt[sc.UDP].dport, sport=pkt[sc.UDP].sport)/\
                            sc.DNS(id=pkt[sc.DNS].id, qd=pkt[sc.DNS].qd, aa = 1, qr=1, \
                                an=sc.DNSRR(rrname=domain,  ttl=600, rdata=redirect_to))
        logging.debug("[Packet Parser] Spoofing %s to IP %s", domain, redirect_to)
        sc.send(spoofed_response, verbose=False)


    def parse_DNS_response(self, pkt):
        """parse DNS packets to extract sld and IP list"""
        response_list = []
        for x in range(pkt[sc.DNS].ancount):
            # filter to find A record
            answer = pkt[sc.DNS].an[x]
            if answer.type in DNS_RECORD_TYPE:
                dns_type = DNS_RECORD_TYPE[answer.type]
                if dns_type == "A" or dns_type == "AAAA":
                    logging.debug("DNS RESPONSE %s : %s", pkt[sc.DNS].an[x].rrname, pkt[sc.DNS].an[x].rdata)
                    response = pkt[sc.DNS].an[x].rrname.decode().rstrip("."), pkt[sc.DNS].an[x].rdata
                    response_list.append(response)
        return response_list


    def parse_DNS(self, pkt):
        is_DNS_query = (pkt[sc.DNS].qr == 0)
        if is_DNS_query:
            # forward DNS queries
            self.forward_packet(pkt)
        else:
            # check that response is not empty
            if pkt[sc.DNS].qdcount > 0 and pkt[sc.DNS].ancount > 0 and pkt.haslayer(sc.DNSRR):
                # parse DNS response
                response_list = self.parse_DNS_response(pkt)
                for r in response_list:
                    fqdn, ip_response = r
                    print(fqdn, ip_response)
                    # logging.debug("[Packet Parser] Domain %s, ip list %s", fqdn, ip_list)
                    # add to pDNS data
                    self.traffic_monitor.add_to_pDNS(fqdn, [ip_response])
                    # add to queried domains:, querier is the destination since packet is a response
                    ip_source = pkt[sc.IP].dst
                    self.traffic_monitor.add_to_queried_domains(ip_source, fqdn, timestamp=int(pkt.time))
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
                    # logging.debug("[Packet Parser] Domain %s does not exist", fqdn)
                    self.traffic_monitor.add_to_pDNS(fqdn, [])
                    self.forward_packet(pkt)
                    # add to queried domains:, querier is the destination since packet is a response
                    ip_source = pkt[sc.IP].dst
                    self.traffic_monitor.add_to_queried_domains(ip_source, fqdn, timestamp=int(pkt.time))


    def parse_ARP(self, pkt):
        """Process an ARP packet and update the ARP table of the host state"""
        if pkt.op == 2:
            # deal with ARP responses
            mac =  pkt[sc.ARP].hwsrc
            ip = pkt[sc.ARP].psrc
            self.traffic_monitor.add_to_ARP_table(ip, mac)
        elif pkt.op == 1:
            mac =  pkt[sc.ARP].hwsrc
            ip = pkt[sc.ARP].psrc
            self.traffic_monitor.add_to_ARP_table(ip, mac)

            # check the queried IP if it is in the local network
            queried_ip = pkt[sc.ARP].pdst
            if IP_is_private(queried_ip):
                # do not query your own device and do not ad gateway to victims
                if queried_ip != self.host_state.host_ip and queried_ip.split('.')[3] != '1':
                    self.traffic_monitor.new_device(queried_ip)


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
        if pkt[sc.IP].src in self._victim_list or pkt[sc.IP].dst == "255.255.255.255":
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
        if proto == sc.TCP:
            flags = pkt.sprintf('%TCP.flags%')
        else:
            flags = "UDP"
        pkt_attributes = FlowPkt(
            inbound=inbound,
            size=len(pkt[proto].payload),
            timestamp=int(pkt.time),
            flags=flags
        )
        self.traffic_monitor.add_to_flow(flow_key, pkt_attributes)


    def parse_DHCP(self, pkt):
        """Parse DHCP packets in order to get the device names"""
        option_dict = {t[0]: t[1] for t in pkt[sc.DHCP].options if isinstance(t, tuple)}
        #check if there is a device name:
        if "hostname" in option_dict:
            device_mac = pkt[sc.Ether].src
            hostname = option_dict["hostname"].decode("utf-8")
            with self.host_state.lock:
                self.host_state.device_names[device_mac] = hostname


    def check_IP_layer(self, pkt):
        """Check the IP layer for unusual behavior: IP spoofing"""
        external_IP = self.host_state.external_ip
        victims_IP = self.host_state.victim_ip_list.copy()
        # determine if packet is query or answer:
        # if the source MAC is a victim's MAC, then it is a query
        try:
            victims_MAC = [self.host_state.arp_table[ip] for ip in victims_IP]
        except KeyError:
            return

        # if it is a victim MAC: the packet is a query
        if pkt[sc.Ether].src in victims_MAC:
            # get IP that corresponds to MAC by reversing the ARP table
            list_IPs = list(self.host_state.arp_table.values())
            list_MACs = list(self.host_state.arp_table.keys())
            mac_associated_IP = list_MACs[list_IPs.index(pkt[sc.Ether].src)]
            packet_IP = pkt[sc.IP].src
            if (packet_IP != mac_associated_IP) and (packet_IP != external_IP):
                if mac_associated_IP.split(".")[3] == "1":
                    # do not consider spoofs for the gateway
                    return
                # logging.warning("[PacketParser] Unknown source IP %s used by MAC %s, may be a spoofed IP", packet_IP, pkt[sc.Ether].src)
                timestamp = int(pkt.time)
                self.host_state.alert_manager.new_alert_IP_spoofed(mac_associated_IP, packet_IP, timestamp)

    def parse_packet(self, pkt):
        try:
            if not sc.Ether in pkt:
                pkt.summary()
                return
            if pkt[sc.Ether].src == self.host_state.host_mac:
                # do not parse outcoming packets
                return

            # only deal with IP packets, which are targetted by ARP spoofing
            if sc.IP in pkt:
                if pkt[sc.IP].dst == self.host_state.host_ip:
                    #do not parse packets destined to our host
                    return
                self.check_IP_layer(pkt)
                if pkt[sc.IP].dst in self._victim_list or pkt[sc.IP].src in self._victim_list or pkt[sc.IP].dst == "255.255.255.255":
                    # packet from or to IPs that are not victims
                    if (sc.UDP in pkt or sc.TCP in pkt) and sc.DNS in pkt:
                        self.parse_DNS(pkt)
                        # do not forward packet here, since it may be spoofed
                    if (sc.UDP in pkt) and pkt[sc.UDP].dport == 5353:
                        # could be mDNS:
                        pkt[sc.UDP].decode_payload_as(sc.DNS)
                        self.parse_DNS(pkt)
                    if sc.DHCP in pkt:
                        self.parse_DHCP(pkt)
                    if sc.TCP in pkt:
                        self.forward_packet(pkt)
                        self.parse_TCP_UDP(pkt, protocol="TCP")
                    if sc.UDP in pkt:
                        self.forward_packet(pkt)
                        self.parse_TCP_UDP(pkt, protocol="UDP")
                    else: # has no known layer
                        # checking for blacklist should not be necessary since DNS is spoofed
                        # forward packet since the packet destination MAC is spoofed
                        self.forward_packet(pkt)
                else:
                    # not a victim, but could be a new device?
                    if IP_is_private(pkt[sc.IP].src):
                        self.traffic_monitor.new_device(pkt[sc.IP].src)
            else:
                # non IP packets
                # we parse ARP packets to try to get more information about the devices in the network
                if sc.ARP in pkt:
                    self.parse_ARP(pkt)
        except OSError:
            # some packets are too big to be sent to sockets, causing OSError, to fix.
            pass


    def prn_call(self, pkt):
        """This is the function that is called by the prn callback in Sniffer"""
        self.count += 1
        if self.count == 1:
            self.host_state.first_timestamp = int(pkt.time)
        if not self.host_state.online:
            if self.count % 25000 == 0:
                logging.info("%s: [PacketParser] %d packets", self.host_state.capture_file.split("/")[-1], self.count)

        safe_run(self.parse_packet, args=[pkt])
        # delay = time.time() - pkt.time
        # self.delays.append((time.time(), delay))