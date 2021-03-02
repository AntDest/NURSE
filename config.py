IP_VICTIMS = [
    "192.168.1.46",
]
BLACKLIST_DOMAINS = [
    "youtube.com",
    "facebook.com",
    "neverssl.com",
    "grenoble.fr" 
]

DATABASE_UPDATE_DELAY = 20

# If QUIT_AFTER > 0, the program will stop after the given number of seconds
QUIT_AFTER = 0
# list of services that can be used to obtain your IP
CHECK_IP_URL_LIST = ["https://checkip.amazonaws.com", "https://ident.me", "https://api.ipify.org"]

# RULES
# values will be evaluated against datasets
TIME_WINDOW = 60        #seconds
MAX_PORTS_PER_HOST = 15
MAX_CONNECTIONS_PER_PORT = 15
MAX_NXDOMAIN = 15