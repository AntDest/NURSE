import threading
import logging
import scapy.all as sc

class Sniffer:
    def __init__(self, host_state):
        self._host_state = host_state
        self.lock = threading.Lock()
        self._active = False
        self.sniffer = sc.AsyncSniffer(
            prn=self._host_state.packet_parser.prn_call,
            )

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
        self.sniffer.stop()

    def _is_active(self):
        """return True if the thread has to stop"""
        with self.lock:
            return self._active