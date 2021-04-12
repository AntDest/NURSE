from src.alert import *


class AlertManager():
    """Centralizing the list of alert events"""
    def __init__(self, host_state):
        self.host_state = host_state
        self.alert_list = []
        self.alert_keys = set()

    def add_to_alert_list(self, alert, key):
        if key not in self.alert_keys:
            self.alert_keys.add(key)
            self.alert_list.append(alert)

    def new_alert_IP_spoofed(self, host_IP, spoofed_IP, timestamp):
        a = AlertIPSpoofed(host_IP, spoofed_IP, timestamp)
        key = f"AlertIPSpoofed:{host_IP}:{spoofed_IP}:{timestamp}"
        self.add_to_alert_list(a, key)

    def new_alert_nxdomain(self, host_IP, timestamp_start, timestamp_end, nx_count):
        a = AlertNXDOMAIN(host_IP, timestamp_start, timestamp_end, nx_count)
        key = f"AlertNXDOMAIN:{host_IP}:{timestamp_start}"
        self.add_to_alert_list(a, key)

    def new_alert_vertical_portscan(self, host_IP, target_IP, timestamp_start, timestamp_end, port_count):
        a = AlertVertPortScanning(host_IP, target_IP, timestamp_start, timestamp_end, port_count)
        key = f"AlertVertPortScanning:{host_IP}:{target_IP}:{timestamp_start}"
        self.add_to_alert_list(a, key)

    def new_alert_horizontal_portscan(self, host_IP, target_port, timestamp_start, timestamp_end, ip_count):
        a = AlertHorizPortScanning(host_IP, target_port, timestamp_start, timestamp_end, ip_count)
        key = f"AlertHorizPortScanning:{host_IP}:{target_port}:{timestamp_start}"
        self.add_to_alert_list(a, key)

    def new_alert_dos(self, host_IP, target_IP, timestamp_start, timestamp_end, connection_count):
        a = AlertDoS(host_IP, target_IP, timestamp_start, timestamp_end, connection_count)
        key = f"AlertDoS:{host_IP}:{target_IP}:{timestamp_start}"
        self.add_to_alert_list(a, key)

    def new_alert_domains(self, host_IP, timestamp_start, timestamp_end, domain_count, threshold):
        a = AlertDomains(host_IP, timestamp_start, timestamp_end, domain_count, threshold)
        key = f"AlertDomains:{host_IP}:{timestamp_start}"
        self.add_to_alert_list(a, key)

    def new_alert_no_dns(self, host_IP, ip_dst, timestamp):
        a = AlertNoDNS(host_IP, ip_dst, timestamp)
        key = f"AlertNoDNS:{host_IP}:{ip_dst}"
        self.add_to_alert_list(a, key)

    def new_alert_blacklisted_ip(self, ip_src, ip_dst, timestamp):
        a = AlertBlacklist(ip_src, ip_dst, timestamp)
        key = f"AlertBlacklist:{ip_src}:{ip_dst}:{timestamp}"
        self.add_to_alert_list(a, key)

    def get_list_as_dict(self):
        dict_list = []
        for i, a in enumerate(self.alert_list):
            alert_dict = {}
            alert_dict["name"] = a.name
            alert_dict["host"] = a.host_IP
            alert_dict["message"] = a.message
            alert_dict["timestamp"] = a.timestamp
            dict_list.append(alert_dict)
        return dict_list

