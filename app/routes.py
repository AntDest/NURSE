import json
import time
from flask import render_template
from app import app

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
@app.route('/index')
def index():
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
        print(key_dict)
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


    return render_template("index.html", data=data)