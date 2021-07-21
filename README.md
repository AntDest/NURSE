# NURSE

This tool is aimed at detecting infected IoT devices in a home network. Launched from a local computer, it intercepts traffic from targetted devices and monitors it to detect potential infections.

At the moment, it allows to intercept the traffic from devices and to block communications between these devices and specific domains using ARP and DNS spoofing.


## Running NURSE

### On Linux
Simply make sure that scapy is installed
`pip3 install scapy`

The tool can be launched with the following command:
`sudo python3 main.py`

Note that it requires administrator privileges due to packet crafting and sending with scapy.

### On Windows
If python is installed on your Windows you can follow the Linux instructions to run the file invoking python from the command line.

Otherwise, you can use the exe files in the folder `run`. There are two files:
- `installer_windows.exe` will help you for the installation of Npcap (if it has not been installed on you machine yet). This software is necessary for scapy and packet crafting to work on Windows.
- the `main` folder, that contains `main.exe` which launches the tool

To run the project for the first time:
- double click on installer_windows.exe
- allow modifications on your computer
- Read the EULA and click on "I agree"
- Click on "Install"
- Wait for the installation to complete
- Click on "Next >"
- Click on "Finish"
- *The tool is now launched*

To run the project later, simply double click on `main.exe`
