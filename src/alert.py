import datetime
from config import MAX_CONNECTIONS_PER_PORT, MAX_NXDOMAIN
class Alert():
    # severity out of 3
    severity = 0
    name = "Alert"
    message = "Basic Alert"
    host_IP: str
    timestamp = 0
    def __init__(self, host_IP, severity, message=""):
        self.message = message
        self.severity = severity
        self.host_IP = host_IP

    def __str__(self):
        return f"{self.name}, Severity: {self.severity}: {self.message} "

class AlertIPSpoofed(Alert):
    name = "IP Spoofed alert"
    def __init__(self, host_IP, spoofed_IP, timestamp):
        severity = 4
        self.spoofed_IP = spoofed_IP
        self.timestamp = timestamp
        message = f"{host_IP} used a spoofed IP {spoofed_IP}"
        super().__init__(host_IP, severity, message)

class AlertNXDOMAIN(Alert):
    name = "NXDOMAIN rate alert"
    def __init__(self, host_IP, timestamp_start, timestamp_end, nx_count):
        severity = min(5, nx_count // MAX_NXDOMAIN)
        self.timestamp = timestamp_start
        d_start = datetime.datetime.fromtimestamp(timestamp_start)
        d_end = datetime.datetime.fromtimestamp(timestamp_end)
        message = f"{host_IP} contacted {nx_count} non-existent domains between {d_start.strftime('%H:%M:%S')} and {d_end.strftime('%H:%M:%S')}"
        super().__init__(host_IP, severity, message)

class AlertVertPortScanning(Alert):
    name = "Port scanning alert"
    def __init__(self, host_IP, target_IP, timestamp_start, timestamp_end, port_count):
        severity = 4
        self.target_IP = target_IP
        self.timestamp = timestamp_start
        d_start = datetime.datetime.fromtimestamp(timestamp_start)
        d_end = datetime.datetime.fromtimestamp(timestamp_end)
        message = f"{host_IP} contacted {port_count} different ports of {target_IP} between {d_start.strftime('%H:%M:%S')} and {d_end.strftime('%H:%M:%S')}"
        super().__init__(host_IP, severity, message)

class AlertHorizPortScanning(Alert):
    name = "Port scanning alert"
    def __init__(self, host_IP, target_port, timestamp_start, timestamp_end, ip_count):
        severity = 4
        self.target_port = target_port
        self.timestamp = timestamp_start
        d_start = datetime.datetime.fromtimestamp(timestamp_start)
        d_end = datetime.datetime.fromtimestamp(timestamp_end)
        message = f"{host_IP} contacted {ip_count} different hosts on port {target_port} between {d_start.strftime('%H:%M:%S')} and {d_end.strftime('%H:%M:%S')}"
        super().__init__(host_IP, severity, message)



class AlertDoS(Alert):
    name = "DoS alert"
    def __init__(self, host_IP, target_IP, timestamp_start, timestamp_end, connection_count):
        severity = min(5, connection_count//MAX_CONNECTIONS_PER_PORT)
        self.target_IP = target_IP
        self.timestamp = timestamp_start
        d_start = datetime.datetime.fromtimestamp(timestamp_start)
        d_end = datetime.datetime.fromtimestamp(timestamp_end)
        message = f"{host_IP} initiated {connection_count} connections with {target_IP} between {d_start.strftime('%H:%M:%S')} and {d_end.strftime('%H:%M:%S')}"
        super().__init__(host_IP, severity, message)

class AlertDomains(Alert):
    name = "Suspicious domains alert"
    def __init__(self, host_IP, timestamp_start, timestamp_end, domain_count, threshold):
        severity = 2
        self.timestamp = timestamp_start
        d_start = datetime.datetime.fromtimestamp(timestamp_start)
        d_end = datetime.datetime.fromtimestamp(timestamp_end)
        message = f"{host_IP} contacted {domain_count} domains with score higher than {threshold} between {d_start.strftime('%H:%M:%S')} and {d_end.strftime('%H:%M:%S')}"
        super().__init__(host_IP, severity, message)

class AlertNoDNS(Alert):
    name = "Hardcoded IP"
    def __init__(self, host_IP, ip_dst, timestamp):
        severity = 2
        self.timestamp = timestamp
        date = datetime.datetime.fromtimestamp(timestamp)
        message = f"{host_IP} contacted {ip_dst} with no DNS query before at {date.strftime('%H:%M:%S')}"
        super().__init__(host_IP, severity, message)

class AlertBlacklist(Alert):
    name = "Blacklisted IP"
    def __init__(self, host_IP, ip_dst, timestamp):
        severity = 2
        self.timestamp = timestamp
        date = datetime.datetime.fromtimestamp(timestamp)
        message = f"{host_IP} contacted {ip_dst} which is blacklisted, time:{date.strftime('%H:%M:%S')}"
        super().__init__(host_IP, severity, message)