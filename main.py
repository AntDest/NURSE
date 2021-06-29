import time
import sys
import logging
import traceback
import argparse
import json
import multiprocessing

from src.HostState import HostState
from src.ARP_spoofer import ARP_spoofer
from src.Sniffer import Sniffer
from src.PacketParser import PacketParser
from src.TrafficMonitor import TrafficMonitor
from src.Server import Server
from src.AlertManager import AlertManager
from src.TrafficAnalyzer import TrafficAnalyzer
from src.utils.utils import StopProgramException

logging_format = "%(asctime)s: %(message)s"
logging.basicConfig(stream=sys.stdout, format=logging_format, level=logging.INFO, datefmt="%H:%M:%S")
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)

def export_to_file(h, output_file):
    logging.debug("[Main] Dumping to file %s", output_file)
    data = {}
    alerts = h.alert_manager.get_list_as_dict()
    data["n_packets"] = h.packet_parser.count
    data["n_alerts"] = len(alerts)
    data["victim_list"] = h.victim_ip_list
    data["alerts"] = alerts
    data["ARP_table"] = h.arp_table
    data["timestamp_start"] = h.first_timestamp
    data["timestamp_last"] = h.last_timestamp
    # data["pDNS"] = h.passive_DNS
    # data["flows"] = h.flows
    # data["domain_scores"] = h.domain_scores
    logging.debug("[Main] Gathered data to dump to %s", output_file)
    try:
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2, cls=SetEncoder)
        print(f"[Main] Dumped data to {output_file}")
    except Exception as e:
        print(data)
        print("\n\n\nCOULD NOT DUMP DATA TO JSON")
        err_msg = 'Exception: %s\n' % e
        err_msg += str(traceback.format_exc()) + '\n\n\n'
        print(err_msg)


def main(online, capture_file, output_file):
    logging.info("[Main] Initializing HostState")
    h = HostState(online)
    h.set_capture_file(capture_file)
    try:

        #initiate all classes of other threads and link them to the host
        logging.info("[Main] Initializing child threads")
        h.ARP_spoof_thread = ARP_spoofer(h)
        h.traffic_monitor = TrafficMonitor(h, h.config.get_config("DATABASE_UPDATE_DELAY"))
        h.packet_parser = PacketParser(h, h.traffic_monitor)
        h.sniffer_thread = Sniffer(h, h.packet_parser)
        h.server_thread = Server(h)
        h.alert_manager = AlertManager(h)
        h.traffic_analyzer = TrafficAnalyzer(h)
        logging.info("[Main] Starting child threads")
        h.start()
        h.main_loop()

    except (KeyboardInterrupt, StopProgramException):
        print("") # breakline after ^C to help reading
        logging.info("[Main] Keyboard Interrupt, ending")
    except Exception as e:
        print(traceback.format_exc())
        print(e)
    finally:
        print("[Main] ---------------------- Ending ----------------------")
        logging.info("[Main] %d packets captured", h.packet_parser.count)
        h.stop()
        if output_file != "":
            export_to_file(h, output_file)

if __name__ == "__main__":
    # prepare multiprocessing for exe files
    multiprocessing.freeze_support()

    parser = argparse.ArgumentParser(description='Options for the IoT inspection program')
    parser.add_argument('--offline', metavar='path', type=str, default="", help='the path to the pcap file')
    parser.add_argument('--output', metavar='path', type=str, default="", help='the path of the output file')
    args = parser.parse_args()
    arg_online = True
    capture_path = ""
    output_path = ""
    if args.offline != "":
        arg_online = False #online at true enables packet sending, packet forwarding
        capture_path = args.offline
    if args.output != "":
        output_path = args.output

    main(arg_online, capture_file=capture_path, output_file=output_path)