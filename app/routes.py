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

@app.template_filter('timestamp_to_hhmmss')
def timestamp_to_hhmmss(t):
    return time.strftime('%H:%M:%S', t)



@app.route('/')
@app.route('/index')
def index():
    hs = get_host_state()
    with hs.lock:
        domain_scores = hs.domain_scores.copy()
        last_update = hs.last_update
    scores_table = [{"domain":k, "score":v} for k,v in domain_scores.items()]
    return render_template("index.html", last_update=last_update, scores_table=scores_table)