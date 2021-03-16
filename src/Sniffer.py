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
        self.packet_parser = packet_parser
        self.filter = lambda p: (p.haslayer(sc.IP) or p.haslayer(sc.ARP))
        self._thread = None

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
            if count%1000 == 0:
                if not self._active:
                    return True
            return False

    def main(self):
        """starts the Sniffer thread. To be called by host state"""
        logging.info("[Sniffer] Sniffer starting")
        with self.lock:
            self._active = True
        if self.host_state.online:
            self.sniffer = sc.AsyncSniffer(
                prn=self.packet_parser.prn_call,
                stop_filter=lambda p: self.stop_filter(self.packet_parser.count)
            )
            self.sniffer.start()
        else:
            sc.sniff(
                    offline=self.host_state.capture_file,
                    prn=self.packet_parser.prn_call,
                    lfilter=self.filter,
                    stop_filter=lambda p: self.stop_filter(self.packet_parser.count),
                    store=False
                )


    def start(self):
        self._thread = threading.Thread(target=self.main)
        self._thread.start()


    def stop(self):
        """starts the Sniffer thread. To be called by host state"""
        with self.lock:
            self._active = False

        logging.info("[Sniffer] Sniffer stopping")
        self._thread.join()

    def _is_active(self):
        """return True if the thread has to stop"""
        with self.lock:
            return self._active