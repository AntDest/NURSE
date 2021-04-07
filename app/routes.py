import time
import logging
from flask import render_template, jsonify
from flask import request
from app import app
from src.utils.utils import is_IPv4
from ipaddress import ip_address
from app.utils import CONVERT_ISO_3166_2_to_1
WEBAPP_CONTEXT = {
    "host_state": None
}

def start_app_thread(host_state):
    WEBAPP_CONTEXT["host_state"] = host_state
    try:
        app.run()
    except OSError:
        pass

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
        device_name = hs.device_names.get(mac, ("",""))[0]
        if device_name != "":
            device_name = ip
        list_devices.append(device_name)
        for timestamp, domain in queried_domains[ip]:
            score =  domain_scores.get(domain,0)
            d = {
                "timestamp": timestamp,
                "device": device_name,
                "domain": domain,
                "score": score
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


import requests
import json
def get_country(ip):
    r = requests.get("http://ip-api.com/json/" + ip)
    ip_data = json.loads(r.text)
    return ip_data.get("countryCode", "")



@app.route("/country_traffic")
def get_traffic_map():
    hs = get_host_state()
    with hs.lock:
        flows = hs.flows
        victim_ip_list = hs.victim_ip_list

    victims_to_dest_data_size = {}
    for flow in flows:
        ip_src = getattr(flow,"IP_src")
        ip_dst = getattr(flow,"IP_dst")
        if ip_address(ip_dst).is_private:
            continue
        if ip_src in victim_ip_list:
            if ip_src not in victims_to_dest_data_size:
                victims_to_dest_data_size[ip_src] = {}
            packets_total_size = sum([p.size for p in flows[flow]])
            if packets_total_size > 0:
                victims_to_dest_data_size[ip_src][ip_dst] = victims_to_dest_data_size[ip_src].get(ip_dst, 0) + packets_total_size

    victim_to_countries = {}
    for ip_src in victims_to_dest_data_size:
        victim_to_countries[ip_src] = {}
        for ip in victims_to_dest_data_size[ip_src]:
            country = get_country(ip)
            if country != "":
                victim_to_countries[ip_src][country] = victim_to_countries[ip_src].get(country, 0) + victims_to_dest_data_size[ip_src][ip]

    csv_string = 'ip,country,count\n'
    for ip in victim_to_countries:
        for country in victim_to_countries[ip]:
            country_code = CONVERT_ISO_3166_2_to_1.get(country, country)
            line = f"{ip},{country_code},{victim_to_countries[ip][country]}\n"
            csv_string += line
    print(csv_string)
    return csv_string

@app.route("/map")
def map_route():
    hs = get_host_state()
    with hs.lock:
        last_update = hs.last_update
    data = {}
    data["last_update"] = last_update
    return(render_template("map.html", data=data))