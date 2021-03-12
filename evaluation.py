import subprocess
import os

capture_folder = "captures"
capture_files = [capture_folder + "/" + c for c in os.listdir(capture_folder)]

for c in capture_files:
    subprocess.run(["python", "main.py", "--offline", c, "--output", "alerts.json"], check=False)
    