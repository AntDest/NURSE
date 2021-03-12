import threading
import logging
import scapy.all as sc

class Sniffer:
    def __init__(self, host_state, packet_parser):
        self.host_state = host_state
        self.lock = threading.Lock()
        self._active = False
        self.filter = lambda p: (p.haslayer(sc.IP) or p.haslayer(sc.ARP)) 
        if self.host_state.online:
            self.sniffer = sc.AsyncSniffer(
                prn=packet_parser.prn_call,
            )
        else:
            if self.host_state.capture_file:
                self.sniffer = sc.AsyncSniffer(
                    offline=self.host_state.capture_file,
                    prn=packet_parser.prn_call,
                    lfilter=self.filter,
                )
            else:
                raise Exception("Error: No capture file provided for offline mode")
    
    def start(self):
        """starts the Sniffer thread. To be called by host state"""
        with self.lock:
            self._active = True

        logging.info("[Sniffer] Sniffer starting")
        self.sniffer.start()

    def stop(self):
        """starts the Sniffer thread. To be called by host state"""
        with self.lock:
            self._active = False

        logging.info("[Sniffer] Sniffer stopping")
        try:
            self.sniffer.stop(join=False)
        except sc.Scapy_Exception:
            pass

    def restart(self):
        """Used to restart the sniffer, especially useful in offline mode to rescan pcap filewith new config"""
        if self._active:
            self.stop()
            self.host_state.reset()
            self.start()

    def _is_active(self):
        """return True if the thread has to stop"""
        with self.lock:
            return self._active