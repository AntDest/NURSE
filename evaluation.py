import subprocess
import os
import json
import time
capture_folder = "evaluation/captures/normal"
capture_files = [capture_folder + "/" + c for c in os.listdir(capture_folder)]

for c in capture_files:
    t1 = time.time()
    output_file = "evaluation/results/" + c.split("/")[-1].split(".pcap")[0] + ".json"
    print(output_file)
    try:
        subprocess.run(
        ["python", "main.py", "--offline", c, "--output", output_file], 
        check=False, 
        # stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    except KeyboardInterrupt:
        pass
    finally:
        t2 = time.time()
        with open(output_file, "r") as fin:
            data = json.load(fin)
            alert_list = data["alerts"]
            n_packets = data["n_packets"]
            packets_per_second = n_packets/(t2-t1)
            print(f"File: {c}\nAlerts: {len(data['alerts'])}\nTime: {t2-t1:.2f}\nPackets per second: {packets_per_second:.1f}")
            if len(alert_list) > 0:
                print(alert_list[:5])
        continue_input = input("Do you want to continue to next file? y/n\n")
        if continue_input.lower() != "y":
            break