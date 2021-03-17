import multiprocessing
import subprocess
import os
import time
import json
import argparse
capture_folder = "evaluation/captures/"
capture_files = {}
capture_files["benign"] = [capture_folder + "normal/" + c for c in os.listdir(capture_folder+"normal/")]
capture_files["malicious"] = [capture_folder + "malicious/" + c for c in os.listdir(capture_folder+"malicious/")]



def evaluate_file(label, capture_file):
    print("EVALUATION OF ", capture_file)
    t1 = time.time()
    output_file = "evaluation/results/" + label + "_" + capture_file.split("/")[-1].split(".pcap")[0] + ".json"
    if os.path.exists(output_file):
        print(output_file, " exists")
        return


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

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--reset', type=bool, nargs="?", const=True, default=False, help='Use it to delete all results')
    args = parser.parse_args()
    if args.reset:
        for f_result in os.listdir("evaluation/results/"):
            os.remove("evaluation/results/" + f_result)
    try:
        processes = []
        starttime = time.time()
        for label in capture_files:
            for c in capture_files[label]:
                p = multiprocessing.Process(target=evaluate_file, args=(label, c))
                processes.append(p)
                p.start()
    except KeyboardInterrupt:
        print("Ending")
    finally:
        for process in processes:
            process.join()

    print('The evaluation took {} seconds'.format(time.time() - starttime))