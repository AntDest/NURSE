from src.alert import AlertIPSpoofed


class AlertManager():
    """Centralizing the list of alert events"""
    def __init__(self, host_state):
        self._host_state = host_state
        self.alert_list = []

    def new_alert_IP_spoofed(self, host_IP, spoofed_IP, timestamp):
        a = AlertIPSpoofed(host_IP, spoofed_IP, timestamp)
        self.alert_list.append(a)