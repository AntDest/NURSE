# IoT-meter

This tool is aimed at detecting infected IoT devices in a home network. Launched from a local computer, it intercepts traffic from targetted devices and monitors it to detect potential infections.

At the moment, it allows to intercept the traffic from devices and to block communications between these devices and specific domains using ARP and DNS spoofing.


## Running the tool

### Configuration

Find the IP of the devices you want to target, and add them in the `config.py` file.
Fill the domains you want to block in the `config.py` file. These domains can be FQDN (Fully Qualified Domain Names) or simply SLDs. Specifying only an SLD will result in a block of the whole domain (e.g. blocking *facebook.com* would also block *analytics.facebook.com*)

### Running
#### On Linux
Simply make sure that scapy is installed
`pip3 install scapy`

The tool can be launched with the following command:
`sudo python3 main.py`

Note that it requires administrator privileges due to packet crafting and sending with scapy.

#### On Windows
If python is installed on your Windows you can follow the Linux instructions to run the file invoking python from the command line.

Otherwise, you can use the exe files in the folder `ìnstaller`. There are two files:
- `installer_windows.exe` will help you for the installation of Npcap (if it has not been installed on you machine yet). This software is necessary for scapy and packet crafting to work on Windows. Double click
- `main.exe` which launches the tool

To run the project for the first time:
- double click on installer_windows.exe
- allow modifications on your computer
- Read the EULA and click on "I agree"
- Click on "Install"
- Wait for the installation to complete
- Click on "Next >"
- Click on "Finish"
- *The tool is now launched*

To run the project later, simply double click on main.exe

*Note*: Changing the configuration may need to recompile the exe files again, this can be done with pyinstaller. (To be patched)

## More technical details

### ARP spoofing
The tool uses a techniques called *ARP spoofing* to intercept traffic from a device: the computer running the program modifies the network configuration to place itself between the targeted device and the router, thus intercepting all the traffic.

This ARP spoofer is a specific implementation since *it does not rely on IP forwarding*. In most ARP spoofing implementations, the final goal is simply to intercept traffic. Therefore, the packets are intercepted, and the packet forwarding is left to the network card. With IP forwarding enabled, when the operation system receives spoofed packets which destination IP does not match the host IP, it forwards the packets to the destination IP. Therefore IP forwarding makes interception possible with ARP spoofing without disconnecting the targetted device from the internet.

However, IP forwarding does not allow packet modification since the packets are automatically forwarded by the operating system before the application layer can modify them. In our implementation, all packets are captured by the Sniffer, then sent to the packet parser, which can modify the packets and choose to forward them manually.

### DNS spoofing
All packets are intercepted by the sniffer and sent to the packet parser to be parsed. The packet parser currently only analyzes DNS packets. Most packets are simply forwarded by the parser, but if one packet happens to be a DNS query to a blacklisted domain, the parser spoofs the DNS response, replacing the reponse with its actual IP. Therefore, the device cannot communicate with blacklisted domains. Replacing the response with our IP also allows to intercept the first queries sent to the domain.

The packet parser also keeps a passive DNS table and can use it in an additional check for blacklisting: all packets going to an IP associated with a blacklisted domain are dropped.