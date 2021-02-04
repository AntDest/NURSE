import datetime
import sys
import traceback
import logging
import threading

_lock = threading.Lock()

# SafeRunError taken from iot-inspector, to prevent crashes
class _SafeRunError(object):
    """Used privately to denote error state in safe_run()."""

    def __init__(self):
        pass


def safe_run(func, args=[], kwargs={}):
    """Returns _SafeRunError() upon failure and logs stack trace."""

    try:
        return func(*args, **kwargs)

    except Exception as e:
        err_msg = '=' * 80 + '\n'
        err_msg += 'Time: %s\n' % datetime.datetime.today()
        err_msg += 'Function: %s, Arguments: %s %s\n' % (func, args, kwargs)
        err_msg += 'Exception: %s\n' % e
        err_msg += str(traceback.format_exc()) + '\n\n\n'

        with _lock:
            sys.stderr.write(err_msg + '\n')
            logging.error(err_msg)

        return _SafeRunError()
