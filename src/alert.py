class Alert():
    # severity out of 3
    severity = 0
    name = "Alert"
    message = "Basic Alert"

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
    name = "IP Spoofed Alert"
    def __init__(self, host_IP, spoofed_IP):
        severity = 2
        self.host_IP = host_IP
        self.spoofed_IP = spoofed_IP
        message = f"{host_IP} used a spoofed IP {spoofed_IP}"
        super().__init__(severity, message)
        
    