class ConfigException(Exception):
    pass

class Config:
    """Holds the configuration values for the program and allow to change them"""
    _config_dict = {
    "DATABASE_UPDATE_DELAY":  5,
    "STOP_AFTER_WITH_NO_INFO":  20,
    "QUIT_AFTER_TIME":  0,
    "QUIT_AFTER_PACKETS":  0,
    "CHECK_IP_URL_LIST":  ["https://checkip.amazonaws.com", "https://ident.me", "https://api.ipify.org"],
    "SSH_PORT_LIST": [22],
    "TELNET_PORT_LIST": [23],
    # the following entries can be modified by the user in the web server
    "ENABLE_BLACKLIST_QUERY": True,
    "BLACKLIST_DOMAINS": ["neverssl.com", "grenoble.fr"],
    "WHITELIST_PORTS":  [80,443],
    "TIME_WINDOW":  60,
    "MAX_PORTS_PER_HOST":  30,
    "MAX_IP_PER_PORT":  30,
    "BRUTEFORCE_CONNECTION_THRESHOLD": 5,
    "MAX_CONNECTIONS_PER_PORT":  120,
    "MAX_NXDOMAIN":  60,
    "DOMAIN_SCORE_THRESHOLD":  5,
    "MAX_DOMAIN_COUNT":  5,
}

    def __init__(self):
        pass

    def __str__(self):
        return str(self._config_dict)
    # STOP_AFTER_WITH_NO_INFO:  20 : Stop after 20s with no more packets
    # If QUIT_AFTER > 0, the program will stop after the given number of seconds
    # list of services that can be used to obtain your IP
    # for thresholds, thr is level 1, level 2 is 2 times this threshold, level 3 is 3 times

    def get_dict(self):
        return self._config_dict.copy()

    def get_config(self, key):
        """Returns a key of the config"""
        if key in self._config_dict:
            return self._config_dict[key]
        else:
            raise ConfigException

    def set_config(self, key, value):
        """Sets a key of the configuration"""
        self._config_dict[key] = value

