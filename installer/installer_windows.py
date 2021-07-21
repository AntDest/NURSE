import urllib.request
import os
import sys

NPCAP_URL = "https://nmap.org/npcap/dist/npcap-1.10.exe"


def get_os():
    """Returns 'mac', 'linux', or 'windows'. Raises RuntimeError otherwise."""
    os_platform = sys.platform

    if os_platform.startswith('darwin'):
        return 'mac'
    elif os_platform.startswith('linux'):
        return 'linux'
    elif os_platform.startswith('win'):
        return 'windows'
    raise RuntimeError('Unsupported operating system.')


if __name__ == "__main__":
    if get_os() != "windows":
        print("[*] this installer is for Windows")
        exit(1)

    print("[*] Downloading Npcap installer")
    r = urllib.request.urlopen(NPCAP_URL)
    with open("npcap_installer.exe", "wb") as fout:
        fout.write(r.read())

    print("[*] Installing Npcap")
    os.system("npcap_installer.exe")

    npcap_path = os.path.join(os.environ['WINDIR'], 'System32', 'Npcap')
    if not os.path.exists(npcap_path):
        print("[x] Npcap installation failed, please restart installer")
        exit(1)
    else:
        print("[v] Npcap installation successful")
        os.remove("npcap_installer.exe")
        print("==> You can now close this window and run NURSE by double clicking on main.exe")
    os.system("PAUSE")