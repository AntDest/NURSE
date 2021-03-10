from src.alert import AlertIPSpoofed, AlertNXDOMAIN, AlertVertPortScanning, AlertHorizPortScanning, AlertDoS, AlertNoDNS


class AlertManager():
    """Centralizing the list of alert events"""
    def __init__(self, host_state):
        self.host_state = host_state
        self.alert_list = []

    def new_alert_IP_spoofed(self, host_IP, spoofed_IP, timestamp):
        a = AlertIPSpoofed(host_IP, spoofed_IP, timestamp)
        self.alert_list.append(a)
    
    def new_alert_nxdomain(self, host_IP, timestamp_start, timestamp_end, nx_count):
        a = AlertNXDOMAIN(host_IP, timestamp_start, timestamp_end, nx_count)
        self.alert_list.append(a)

    def new_alert_vertical_portscan(self, host_IP, target_IP, timestamp_start, timestamp_end, port_count):
        a = AlertVertPortScanning(host_IP, target_IP, timestamp_start, timestamp_end, port_count)
        self.alert_list.append(a)

    def new_alert_horizontal_portscan(self, host_IP, target_port, timestamp_start, timestamp_end, ip_count):
        a = AlertHorizPortScanning(host_IP, target_port, timestamp_start, timestamp_end, ip_count)
        self.alert_list.append(a)
    
    def new_alert_dos(self, host_IP, target_IP, timestamp_start, timestamp_end, connection_count):
        a = AlertDoS(host_IP, target_IP, timestamp_start, timestamp_end, connection_count)
        self.alert_list.append(a)

    def new_alert_domains(self, host_IP, timestamp_start, timestamp_end, domain_count, threshold):
        a = AlertDomains(host_IP, timestamp_start, timestamp_end, domain_count, threshold)
        self.alert_list.append(a)

    def new_alert_no_dns(self, host_IP, ip_dst, timestamp):
        a = AlertNoDNS(host_IP, ip_dst, timestamp)
        self.alert_list.append(a)

