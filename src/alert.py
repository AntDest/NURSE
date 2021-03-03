import datetime

class Alert():
    # severity out of 3
    severity = 0
    name = "Alert"
    message = "Basic Alert"
    timestamp = 0
    def __init__(self, severity, message=""):
        self.message = message
        self.severity = severity

    def set_severity(self, value):
        if value < 0 or value > 3:
            print(f"invalid value {value} for alert severity")
            return
        else:
            self.severity = value

    def __str__(self):
        return f"{self.name}, Severity: {self.severity}: {self.message} "

class AlertIPSpoofed(Alert):
    name = "IP Spoofed alert"
    def __init__(self, host_IP, spoofed_IP, timestamp):
        severity = 2
        self.host_IP = host_IP
        self.spoofed_IP = spoofed_IP
        self.timestamp = timestamp
        message = f"{host_IP} used a spoofed IP {spoofed_IP}"
        super().__init__(severity, message)

class AlertNXDOMAIN(Alert):
    name = "NXDOMAIN rate alert"
    def __init__(self, host_IP, timestamp_start, timestamp_end, nx_count):
        severity = 2
        self.host_IP = host_IP
        self.timestamp = timestamp_start
        d_start = datetime.datetime.fromtimestamp(timestamp_start)
        d_end = datetime.datetime.fromtimestamp(timestamp_end)
        message = f"{host_IP} contacted {nx_count} non-existent domains between {d_start.strftime('%H:%M:%S')} and {d_end.strftime('%H:%M:%S')}"
        super().__init__(severity, message)

class AlertPortScanning(Alert):
    name = "Port scanning alert"
    def __init__(self, host_IP, target_IP, timestamp_start, timestamp_end, port_count):
        severity = 2
        self.host_IP = host_IP
        self.target_IP = target_IP
        self.timestamp = timestamp_start
        d_start = datetime.datetime.fromtimestamp(timestamp_start)
        d_end = datetime.datetime.fromtimestamp(timestamp_end)
        message = f"{host_IP} contacted {port_count} different ports of {target_IP} between {d_start.strftime('%H:%M:%S')} and {d_end.strftime('%H:%M:%S')}"
        super().__init__(severity, message)


class AlertDoS(Alert):
    name = "DoS alert"
    def __init__(self, host_IP, target_IP, timestamp_start, timestamp_end, connection_count):
        severity = 2
        self.host_IP = host_IP
        self.target_IP = target_IP
        self.timestamp = timestamp_start
        d_start = datetime.datetime.fromtimestamp(timestamp_start)
        d_end = datetime.datetime.fromtimestamp(timestamp_end)
        message = f"{host_IP} initiated {connection_count} connections with {target_IP} between {d_start.strftime('%H:%M:%S')} and {d_end.strftime('%H:%M:%S')}"
        super().__init__(severity, message)
