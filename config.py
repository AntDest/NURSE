IP_VICTIMS = [
    ]
BLACKLIST_DOMAINS = [
    "youtube.com",
    "facebook.com",
    "neverssl.com",
    "grenoble.fr"
]

ENABLE_BLACKLIST_QUERY = True  # turn to false to disable queries to spamhaus
DATABASE_UPDATE_DELAY = 5
# Stop after 5 iterations with no more packets
STOP_AFTER_WITH_NO_INFO = 20
# If QUIT_AFTER > 0, the program will stop after the given number of seconds
QUIT_AFTER_TIME = 0
QUIT_AFTER_PACKETS = 0


# list of services that can be used to obtain your IP
CHECK_IP_URL_LIST = ["https://checkip.amazonaws.com", "https://ident.me", "https://api.ipify.org"]

# RULES
WHITELIST_PORTS = [80,443]
# values will be evaluated against datasets
TIME_WINDOW = 60       #seconds
MAX_PORTS_PER_HOST = 30
MAX_IP_PER_PORT = 30
MAX_CONNECTIONS_PER_PORT = 120  # level 1, level 2 is 2 times this threshold, level 3 is 3 times
MAX_NXDOMAIN = 60

DOMAIN_SCORE_THRESHOLD = 5
MAX_DOMAIN_COUNT = 5