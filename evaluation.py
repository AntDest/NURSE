import subprocess
import os
import json
import time
capture_folder = "captures/normal"
capture_files = [capture_folder + "/" + c for c in os.listdir(capture_folder)]

for c in capture_files:
    t1 = time.time()
    subprocess.run(
        ["python", "main.py", "--offline", c, "--output", "alerts.json"], 
        check=False, 
        # stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    t2 = time.time()
    with open("alerts.json", "r") as fin:
        alert_list = json.load(fin)
        print(c, len(alert_list), t2-t1)
        print(alert_list[:5])