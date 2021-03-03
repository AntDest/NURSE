from src.alert import AlertIPSpoofed, AlertNXDOMAIN, AlertPortScanning, AlertDoS


class AlertManager():
    """Centralizing the list of alert events"""
    def __init__(self, host_state):
        self._host_state = host_state
        self.alert_list = []

    def new_alert_IP_spoofed(self, host_IP, spoofed_IP, timestamp):
        a = AlertIPSpoofed(host_IP, spoofed_IP, timestamp)
        self.alert_list.append(a)
    
    def new_alert_nxdomain(self, host_IP, timestamp_start, timestamp_end, nx_count):
        a = AlertNXDOMAIN(host_IP, timestamp_start, timestamp_end, nx_count)
        self.alert_list.append(a)

    def new_alert_portscan(self, host_IP, target_IP, timestamp_start, timestamp_end, port_count):
        a = AlertPortScanning(host_IP, target_IP, timestamp_start, timestamp_end, port_count)
        self.alert_list.append(a)
    
    def new_alert_dos(self, host_IP, target_IP, timestamp_start, timestamp_end, connection_count):
        a = AlertDoS(host_IP, target_IP, timestamp_start, timestamp_end, connection_count)
        self.alert_list.append(a)