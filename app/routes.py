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
        last_update = hs.last_update
        flows = hs.flows.copy()
    scores_table = [{"domain":k, "score":v} for k,v in domain_scores.items()]

    flows_list = []
    for key in flows:
        key_dict = {}
        k = key._asdict()
        for key_name in k:
            key_dict[key_name] = getattr(key, key_name)
        for pkt in flows[key]:
            line_dict = key_dict.copy()
            for key_name in pkt._asdict():
                line_dict[key_name] = getattr(pkt, key_name)
            flows_list.append(line_dict)

    data = {
        "scores": scores_table,
        "last_update": last_update,
        "flows": flows_list
    }

    return render_template("scores.html", data=data)

@app.route("/devices")
def device_list():
    hs = get_host_state()
    data = {
        "last_update": hs.last_update,
        "device_list": hs.get_device_list()
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