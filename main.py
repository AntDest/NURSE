import time
import sys
import logging
import traceback
import argparse

from src.HostState import HostState
from src.ARP_spoofer import ARP_spoofer
from src.Sniffer import Sniffer
from src.PacketParser import PacketParser
from src.TrafficMonitor import TrafficMonitor
from src.Server import Server
from src.AlertManager import AlertManager
from src.TrafficAnalyzer import TrafficAnalyzer
import config
from src.utils.utils import StopProgramException

logging_format = "%(asctime)s: %(message)s"
logging.basicConfig(stream=sys.stdout, format=logging_format, level=logging.DEBUG, datefmt="%H:%M:%S")
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

def main(online, capture_file):
    logging.info("[Main] Initializing HostState")
    h = HostState(online)
    h.set_capture_file(capture_file)
    try:
        h.blacklist_domains = config.BLACKLIST_DOMAINS
        h.victim_ip_list = config.IP_VICTIMS

        #initiate all classes of other threads and link them to the host
        logging.info("[Main] Initializing child threads")
        h.ARP_spoof_thread = ARP_spoofer(h)
        h.traffic_monitor = TrafficMonitor(h, config.DATABASE_UPDATE_DELAY)
        h.packet_parser = PacketParser(h, h.traffic_monitor)
        h.sniffer_thread = Sniffer(h, h.packet_parser)
        h.server_thread = Server(h)
        h.alert_manager = AlertManager(h)
        h.traffic_analyzer = TrafficAnalyzer(h)
        logging.info("[Main] Starting child threads")
        h.start()
        if config.QUIT_AFTER > 0:
            time.sleep(config.QUIT_AFTER)
        else:
            while True:
                continue
    except (KeyboardInterrupt, StopProgramException):
        print("") # breakline after ^C to help reading
        logging.info("[Main] Keyboard Interrupt, ending")
    except Exception as e:
        print(traceback.format_exc())
        print(e)
    finally:
        h.stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Options for the IoT inspection program')
    parser.add_argument('--offline', metavar='path', type=str, default="", help='the path to the pcap file')
    args = parser.parse_args()
    if args.offline != "":
        online = False #online at true enables packet sending, packet forwarding
        capture_path = args.offline    
        # logging.getLogger().setLevel(logging.WARNING)
    else:
        online = True
        capture_path = ""
    main(online, capture_file=capture_path)