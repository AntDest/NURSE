import datetime
import logging
import sys
import traceback
import threading
import scapy.all as sc
import socket

from collections import namedtuple
from typing import NamedTuple

_lock = threading.Lock()

def is_IPv4(ip_string):
    """Returns true if the string is an IPv4: 4 digits < 255, separated by dots"""
    digit_list = ip_string.split(".")
    if len(digit_list) != 4:
        return False
    for d in digit_list:
        if int(d) > 255:
            return False
    return True


# namedtuple for flows key and flow packets:
FlowKey = namedtuple("FlowKey",["IP_src", "IP_dst", "port_src", "port_dst", "protocol"])
class FlowPkt(NamedTuple):
    inbound: bool
    size: int
    timestamp: int


def merge_dict(x,y):
    z = x.copy()   # start with x's keys and values
    z.update(y)    # modifies z with y's keys and values & returns None
    return z



# SafeRunError taken from iot-inspector, to prevent crashes
class _SafeRunError(object):
    """Used privately to denote error state in safe_run()."""

    def __init__(self):
        pass


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
            sys.stderr.write(err_msg + '\n')
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



def get_device_name(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
    except:
        name = ""
    # strip the ".home suffix"
    if name[-5:] == ".home":
        name = name[:-5]
    return name