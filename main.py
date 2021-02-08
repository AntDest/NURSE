import time
import sys
import logging
import traceback

from HostState import HostState



logging_format = "%(asctime)s: %(message)s"
logging.basicConfig(stream=sys.stdout, format=logging_format, level=logging.DEBUG, datefmt="%H:%M:%S")
h = HostState()
try:
    h.start()
    time.sleep(120)
except KeyboardInterrupt:
    print("") # breakline after ^C to help reading
    logging.info("[Main] Keyboard Interrupt, ending")
except Exception as e:
    print(traceback.format_exc())
    print(e)
finally:
    h.stop()
