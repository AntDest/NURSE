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
WHITELIST_PORTS = [80,443]
# values will be evaluated against datasets
TIME_WINDOW = 60        #seconds
MAX_PORTS_PER_HOST = 30
MAX_IP_PER_PORT = 30
MAX_CONNECTIONS_PER_PORT = 30
MAX_NXDOMAIN = 60

DOMAIN_SCORE_THRESHOLD = 5
MAX_DOMAIN_COUNT = 2