import threading
import logging
import time
import scapy.all as sc
from config import QUIT_AFTER_PACKETS, DATABASE_UPDATE_DELAY
class Sniffer:
    def __init__(self, host_state, packet_parser):
        self.host_state = host_state
        self.lock = threading.Lock()
        self._active = False
        self.filter = lambda p: (p.haslayer(sc.IP) or p.haslayer(sc.ARP)) 
        if self.host_state.online:    
            self.sniffer = sc.AsyncSniffer(
                prn=packet_parser.prn_call,
                stop_filter=lambda p: self.stop_filter(packet_parser.count)
            )
        else:
            if self.host_state.capture_file:
                self.sniffer = sc.AsyncSniffer(
                    offline=self.host_state.capture_file,
                    prn=packet_parser.prn_call,
                    lfilter=self.filter,
                    stop_filter=lambda p: self.stop_filter(packet_parser.count)
                )
            else:
                raise Exception("Error: No capture file provided for offline mode")
    
    def stop_filter(self, count):
        if QUIT_AFTER_PACKETS > 0 and count >= QUIT_AFTER_PACKETS:
            # leave some time for data to be updated and analyzed
            time.sleep(2*DATABASE_UPDATE_DELAY)
            # tell the host state to terminate
            logging.info("[Sniffer] stopping because of packet limit")
            self.host_state.active = False
            # return True to stop the scapy sniffer
            return True
        else:
            return False

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