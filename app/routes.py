import time
import logging
from flask import render_template, jsonify
from flask import request, redirect
from app import app
from src.utils.utils import is_IPv4, count_total_bytes_in_flow, IP_is_private
from app.utils_data import CONVERT_ISO_3166_2_to_1
from app.utils import humanbytes, validate_domain_string
import requests
import json

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
        if IP_is_private(ip_dst):
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
    return csv_string

@app.route("/map")
def map_route():
    hs = get_host_state()
    with hs.lock:
        last_update = hs.last_update
    data = {}
    data["last_update"] = last_update
    return(render_template("map.html", data=data))

@app.route("/domains")
def domains_bytes():
    hs = get_host_state()
    with hs.lock:
        last_update = hs.last_update
        flows = hs.flows.copy()
        domain_scores = hs.domain_scores.copy()
        queried_domains = hs.queried_domains.copy()
        arp_table = hs.arp_table.copy()
        device_names = hs.device_names.copy()

    #count bytes per domain
    # keys are (device_name) values are dict with key domain and values (sent_bytes, received_bytes)
    bytes_per_domain = {}
    for flow in flows:
        ip_src = getattr(flow, "IP_src")
        ip_dst = getattr(flow, "IP_dst")
        domain = hs.reverse_pDNS(ip_dst)
        # if domain == "unknown_domain":
            # domain = ip_dst
        flow_pkt_list = flows[flow]
        sent_bytes, received_bytes = count_total_bytes_in_flow(flow_pkt_list)
        if ip_src not in bytes_per_domain:
            bytes_per_domain[ip_src] = {}
        if domain not in bytes_per_domain[ip_src]:
            bytes_per_domain[ip_src][domain] = (sent_bytes, received_bytes)
        else:
            bytes_per_domain[ip_src][domain] = (bytes_per_domain[ip_src][domain][0] + sent_bytes, bytes_per_domain[ip_src][domain][1] + received_bytes)

    table = []
    list_devices = set()
    for ip in bytes_per_domain:
        for domain in bytes_per_domain[ip]:
            line = {}
            device_name = device_names.get(arp_table.get(ip, ""), (ip,""))[0]
            list_devices.add(device_name)
            line["ip"] = ip
            line["device_name"] = device_name
            line["domain"] = domain
            line["sent_bytes"] = humanbytes(bytes_per_domain[ip][domain][0])
            line["received_bytes"] = humanbytes(bytes_per_domain[ip][domain][1])
            if domain in domain_scores:
                line["score"] = round(domain_scores[domain],2)
            else:
                line["score"] = ""
            table.append(line)
    data = {
        "last_update": last_update,
        "list_devices": list(list_devices),
        "table_domains": table
    }
    return render_template("domains.html", data=data)


@app.route("/config")
def config_route():
    hs = get_host_state()
    with hs.lock:
        config_dict = hs.config.get_dict()
    return render_template("config.html", config=config_dict)


@app.route("/update_config", methods=["POST"])
def update_config():
    input_blacklist = request.form["blacklist_domains"].split("\n")
    blacklist_domains = [domain.strip() for domain in input_blacklist if validate_domain_string(domain.strip())]

    input_whitelist = request.form["whitelist_domains"].split("\n")
    whitelist_domains = [domain.strip() for domain in input_whitelist if validate_domain_string(domain.strip())]

    input_enable_ip_blacklist = (request.form.get("enable_ip_blacklist", 'off') == "on")
    input_time_window = int(request.form["time_window"])

    input_ports_whitelist = request.form["whitelist-ports"].split("\n")
    input_ports_whitelist = [port.strip() for port in input_ports_whitelist]

    input_max_ports_per_host = int(request.form["MAX_PORTS_PER_HOST"])
    input_max_ip_per_port = int(request.form["MAX_IP_PER_PORT"])

    input_max_connections = int(request.form["MAX_CONNECTIONS_PER_PORT"])
    input_max_nxdomains = int(request.form["MAX_NXDOMAIN"])
    input_max_domain_count = int(request.form["MAX_DOMAIN_COUNT"])
    input_domain_score = int(request.form["DOMAIN_SCORE_THRESHOLD"])

    # update the config
    hs = get_host_state()
    with hs.lock:
        hs.config.set_config("BLACKLIST_DOMAINS", blacklist_domains)
        hs.config.set_config("WHITELIST_DOMAINS", whitelist_domains)
        hs.config.set_config("TIME_WINDOW", input_time_window)
        hs.config.set_config("ENABLE_BLACKLIST_QUERY", input_enable_ip_blacklist)
        hs.config.set_config("WHITELIST_PORTS", input_ports_whitelist)
        hs.config.set_config("MAX_PORTS_PER_HOST", input_max_ports_per_host)
        hs.config.set_config("MAX_IP_PER_PORT", input_max_ip_per_port)
        hs.config.set_config("MAX_CONNECTIONS_PER_PORT", input_max_connections)
        hs.config.set_config("MAX_DOMAIN_COUNT", input_max_domain_count)
        hs.config.set_config("MAX_NXDOMAIN", input_max_nxdomains)
        hs.config.set_config("DOMAIN_SCORE_THRESHOLD", input_domain_score)
    print(hs.config.get_dict())
    return redirect("/config", code=302)