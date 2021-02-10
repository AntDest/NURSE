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
    return time.ctime(t) # datetime.datetime.fromtimestamp(s)




@app.route('/')
@app.route('/index')
def index():
    hs = get_host_state()
    with hs.lock:
        pDNS = hs.passive_DNS.copy()
        last_update = hs.last_update
    domain_list = list(pDNS.keys())
    return render_template("index.html", last_update=last_update, domains=domain_list)