import datetime
import logging
import traceback
import threading
import scapy.all as sc
import socket
import requests
import json
import time
import multiprocessing # to timeout socket

from collections import namedtuple
from typing import NamedTuple
from src.HostState import HostState

_lock = threading.Lock()


class StopProgramException(Exception):
    pass


def disable_if_offline(f):
    def wrapper(*args, **kwargs):
        if len(args) > 0 and hasattr(args[0], "host_state") and isinstance(args[0].host_state, HostState):
            # if we have a host_state
            if args[0].host_state.online:
                # we are online, run the function:
                return f(*args, **kwargs)
            else:
                # do not run the function as we are in offline mode
                # logging.debug("Disabled function %s.%s in offline mode", args[0].__class__.__name__, f.__name__)
                pass
        else:
            print("Decorator ERROR: ", args, hasattr(args[0], "host_state"))
    return wrapper








def is_IPv4(ip_string):
    """Returns true if the string is an IPv4: 4 digits < 255, separated by dots"""
    digit_list = ip_string.split(".")
    if len(digit_list) != 4:
        return False
    for d in digit_list:
        if int(d) > 255:
            return False
    return True


def get_vendor_from_mac(mac):
    """Get the vendor from the MAC using an API"""
    url = "https://mac2vendor.com/api/v4/mac/"
    mac_str = "".join(mac.split(":")[:3])
    try:
        r = requests.get(url + mac_str)
        response = json.loads(r.text)
        if not response["success"]:
            return "Unknown"
        else:
            return response["payload"][0]["vendor"]
    except:
        return "Unknown"


# namedtuple for flows key and flow packets:
FlowKey = namedtuple("FlowKey",["IP_src", "IP_dst", "port_src", "port_dst", "protocol"])
class FlowPkt(NamedTuple):
    inbound: bool
    size: int
    timestamp: int
    flags: str

def merge_dict(x,y):
    z = x.copy()   # start with x's keys and values
    z.update(y)    # modifies z with y's keys and values & returns None
    return z


def count_total_bytes_in_flow(flow_pkt_list):
    sent_bytes = 0
    recv_bytes = 0

    for pkt in flow_pkt_list:
        if pkt.inbound:
            sent_bytes += pkt.size
        else:
            recv_bytes += pkt.size
    return sent_bytes, recv_bytes



# SafeRunError taken from iot-inspector, to prevent crashes
class _SafeRunError(object):
    """Used privately to denote error state in safe_run()."""

    def __init__(self):
        pass

def restart_on_error(func, args=[], kwargs={}):
    """restarts when a saferun error is encountered"""
    while True:
        result = safe_run(func, args, kwargs)
        if isinstance(result, _SafeRunError):
            time.sleep(1)
            continue

        return result


def safe_run(func, args=[], kwargs={}):
    """Returns _SafeRunError() upon failure and logs stack trace."""

    try:
        return func(*args, **kwargs)

    except Exception as e:
        err_msg = '=' * 80 + '\n'
        err_msg += 'Time: %s\n' % datetime.datetime.today()
        err_msg += 'Function: %s, Arguments: %s %s\n' % (func, args, kwargs)
        err_msg += 'Exception: %s\n' % e
        err_msg += str(traceback.format_exc()) + '\n\n\n'

        with _lock:
            logging.error(err_msg)

        return _SafeRunError()


def get_mac(ip_address):
    """Sends an ARP request and waits for a reply to obtain the MAC of the given IP address"""
    mac_query = sc.ARP(op = 1, hwdst = "ff:ff:ff:ff:ff:ff", pdst = ip_address)
    mac_query_ans, _ = sc.sr(mac_query, timeout=5, verbose=False)
    for _, mac_query_response in mac_query_ans:
        return mac_query_response[sc.ARP].hwsrc
    # if no response, return None
    return None


def get_device_name(ip, gateway_ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
    except:
        try:
            ip_reverse = ".".join(ip.split('.')[::-1])
            dns_response = sc.sr1(sc.IP(dst=gateway_ip)/sc.UDP() / sc.DNS(rd=1, qd=sc.DNSQR(qname=ip_reverse + ".in-addr.arpa", qtype='PTR')), verbose=0)
            name = dns_response[sc.DNS].an[0].rdata.decode()
        except:
            name = ""
    # strip the ".home suffix"
    name = name.rstrip(".")
    if name[-5:] == ".home":
        name = name[:-5]
    return name

def query_dns(url):
    try:
        ip = socket.gethostbyname(url)
        return ip
    except socket.gaierror:
        return ""

def check_ip_blacklist(ip):
    ip_reverse = ".".join(ip.split(".")[::-1])
    url = ip_reverse + "." + "zen.spamhaus.org"
    logging.debug("[Utils] Blacklist: query for %s (url=%s)", ip, url)
    # result codes legend here: https://www.spamhaus.org/zen/
    try:
        dns_query_pool = multiprocessing.Pool()
        pool_result = dns_query_pool.apply_async(query_dns, (url, ))
        database_response = pool_result.get(5)
    except multiprocessing.TimeoutError:
        database_response = ""
    if database_response != "":
        if database_response in ["127.0.0." + str(i) for i in range(2,8)]:
            return True
    return False
