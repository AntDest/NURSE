import multiprocessing
import subprocess
import os
import time
import json
capture_folder = "evaluation/captures/"
capture_files = {}
capture_files["benign"] = [capture_folder + "normal/" + c for c in os.listdir(capture_folder+"normal/")]
capture_files["malicious"] = [capture_folder + "malicious/" + c for c in os.listdir(capture_folder+"malicious/")]



def evaluate_file(capture_file):
    t1 = time.time()
    output_file = "evaluation/results/" + capture_file.split("/")[-1].split(".pcap")[0] + ".json"
    if os.path.exists(output_file):
        print(output_file, " exists")
    subprocess.run(
        ["python", "main.py", "--offline", capture_file, "--output", output_file],
        check=False,
        # stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    t2 = time.time()
    count = 0
    while not os.path.exists(output_file) and count < 5:
        time.sleep(10)
        count += 1
    if not os.path.exists(output_file):
        print("OUTPUT FILE {} was not generated".format(output_file))
        return
    with open(output_file, "r") as fin:
        data = json.load(fin)
        alert_list = data["alerts"]
        n_packets = data["n_packets"]
        packets_per_second = n_packets/(t2-t1)
        print(f"\tFile: {capture_file} \
                \n\tAlerts: {len(data['alerts'])}\
                \n\tPackets: {n_packets}, Time: {t2-t1:.2f}, (Packets per second: {packets_per_second:.1f})"
            )
        if len(alert_list) > 0:
            print(alert_list[:5])


if __name__ == '__main__':
    try:
        processes = []
        starttime = time.time()
        for c in capture_files["benign"] + capture_files["malicious"]:
            p = multiprocessing.Process(target=evaluate_file, args=(c,))
            processes.append(p)
            p.start()
    except KeyboardInterrupt:
        print("Ending")
    finally:
        for process in processes:
            process.join()

    print('The evaluation took {} seconds'.format(time.time() - starttime))