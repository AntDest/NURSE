import threading
import logging

from app.routes import start_app_thread

class Server:
    def __init__(self, host_state):
        self.host_state = host_state
        self.lock = threading.Lock()
        self._active = False

        self.thread = threading.Thread(target=start_app_thread, args=[host_state])
        self.thread.daemon = True
        
    def start(self):
        self.thread.start()
        logging.info("[Server] Starting server")
