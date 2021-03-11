import time
import logging
from flask import render_template
from flask import request
from app import app
from src.utils.utils import is_IPv4

WEBAPP_CONTEXT = {
    "host_state": None
}

def start_app_thread(host_state):
    WEBAPP_CONTEXT["host_state"] = host_state
    app.run()

def get_host_state():
    if WEBAPP_CONTEXT["host_state"]:
        return WEBAPP_CONTEXT["host_state"]
    else:
        raise Exception("No host_state linked to web app")

@app.template_filter('timestamp_to_date')
def timestamp_to_date(t):
    return time.ctime(t)



@app.route('/')
@app.route('/domains')
def domain_list():
    hs = get_host_state()
    with hs.lock:
        domain_scores = hs.domain_scores.copy()
        queried_domains = hs.queried_domains.copy()
        last_update = hs.last_update
    
    domain_table = []
    list_devices = []
    for ip in queried_domains:
        mac = hs.arp_table[ip]
        if mac in hs.device_names:
            device_name = hs.device_names[mac][0]
        else:
            device_name = ip
        list_devices.append(device_name)
        for timestamp, domain in queried_domains[ip]:
            d = {
                "timestamp": timestamp,
                "device": device_name,
                "domain": domain,
                "score": domain_scores[domain]
            }
            domain_table.append(d)
    data = {
        "list_devices": list_devices,
        "domain_table": domain_table,
        "last_update": last_update,
    }

    return render_template("scores.html", data=data)

@app.route("/devices")
def device_list():
    hs = get_host_state()
    data = {
        "last_update": hs.last_update,
        "device_list": hs.get_device_list(),
        "offline": not hs.online
    }
    return render_template("devices.html", data=data)

@app.route("/update_device")
def update_device():
    ip = request.args.get("ip")
    enable = request.args.get("enable")
    if ip is None or enable is None:
        logging.error("/update_device missing parameters: ip=%s and enable=%s", ip, enable)
        return
    # convert true to True and false to False
    enable = (enable == "true")
    hs = get_host_state()
    if enable and ip not in hs.victim_ip_list:
        if is_IPv4(ip):
            hs.add_to_victim_list(ip)
            return "True"
    elif not enable and ip in hs.victim_ip_list:
        hs.remove_from_victim_list(ip)
        return "True"
    else:
        return "False"

@app.route("/alerts")
def alerts():
    data = {}
    hs = get_host_state()
    with hs.lock:
        alert_list = hs.alert_manager.alert_list.copy()
        data["last_update"] = hs.last_update
    data["alerts"] = []
    for a in alert_list:
        d = {}
        d["name"] = a.name
        d["message"] = a.message
        d["timestamp"] = a.timestamp
        data["alerts"].append(d)
    return render_template("alerts.html", data=data)