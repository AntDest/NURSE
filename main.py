import time
import sys
import logging
import traceback

from src.HostState import HostState
from src.ARP_spoofer import ARP_spoofer
from src.Sniffer import Sniffer
from src.PacketParser import PacketParser
from src.TrafficMonitor import TrafficMonitor

from config import *

logging_format = "%(asctime)s: %(message)s"
logging.basicConfig(stream=sys.stdout, format=logging_format, level=logging.DEBUG, datefmt="%H:%M:%S")
h = HostState()
try:
    h.blacklist_domains = BLACKLIST_DOMAINS
    h.victim_ip_list = IP_VICTIMS

    #initiate all classes of other threads and link them to the host
    h.ARP_spoof_thread = ARP_spoofer(h)
    h.traffic_monitor = TrafficMonitor(h, DATABASE_UPDATE_DELAY)
    h.packet_parser = PacketParser(h, h.traffic_monitor)
    h.sniffer_thread = Sniffer(h, h.packet_parser)
    h.start()

    if QUIT_AFTER > 0:
        time.sleep(QUIT_AFTER)
    else:
        while True:
            continue
except KeyboardInterrupt:
    print("") # breakline after ^C to help reading
    logging.info("[Main] Keyboard Interrupt, ending")
except Exception as e:
    print(traceback.format_exc())
    print(e)
finally:
    h.stop()
