import multiprocessing
import subprocess
import os
import time
import json
import argparse
import logging
capture_folder = "evaluation/captures/"
capture_files = {}
capture_files["benign"] = [capture_folder + "normal/" + c for c in os.listdir(capture_folder+"normal/") if c[-5:] == ".pcap"]
capture_files["malicious"] = [capture_folder + "malicious/" + c for c in os.listdir(capture_folder+"malicious/") if c[-5:] == ".pcap"]



def evaluate_file(capture_file):
    #add file name to logger
    logger = logging.getLogger()  # Logger
    logger_handler = logging.StreamHandler()  # Handler for the logger
    logger.addHandler(logger_handler)
    logger_handler.setFormatter(logging.Formatter(f'{capture_file.split("/")[-1]} %(message)s'))

    label = capture_file.split("/")[-2]
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
                \n\tAlerts: {len(alert_list)}\
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
        pool = multiprocessing.Pool(4)
        starttime = time.time()
        # processes = []
        # for c in capture_files["benign"] + capture_files["malicious"]:
            # p = multiprocessing.Process(target=evaluate_file, args=(c,))
            # processes.append(p)
            # p.start()
        pool.map(evaluate_file, capture_files["benign"] + capture_files["malicious"])

    except KeyboardInterrupt:
        print("Ending")
    finally:
        # for process in processes:
            # process.join()
        pass
    print('The evaluation took {} seconds'.format(time.time() - starttime))