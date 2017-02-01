"""
Invokes webserver to be run at 127.0.0.1:2080
Should be run as: python3 -m ttproto.tat_coap
"""
import select
import logging
import signal
import os
import errno
from ttproto import *


### TTPROTO CONSTANTS ###
COMPONENT_ID = 'tat'

# Directories
DATADIR = "data"
TMPDIR = "tmp"
LOGDIR = "log"

SERVER_CONFIG = ("0.0.0.0", 2080)
# either amqp (amqp interface) or http (webserver)
INTERFACE = 'amqp'
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

def shutdown():
    global __shutdown
    __shutdown = True


def reopen_log_file(signum, frame):
    global log_file
    log_file = open(os.path.join(LOGDIR, "ttproto.tat_coap.log"), "a")


if __name__ == "__main__":



    job_id = 0

    __shutdown = False

    for d in TMPDIR, DATADIR, LOGDIR:
        try:
            os.makedirs(d)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise


    reopen_log_file(None, None)
    # log rotation
    # -> reopen the log file upon SIGHUP
    signal.signal(signal.SIGHUP, reopen_log_file)


    if INTERFACE == 'http':
        from .webserver import *

        def reopen_log_file(signum, frame):
            global log_file
            log_file = open(os.path.join(LOGDIR, "webserver.log"), "a")

        server = http.server.HTTPServer(SERVER_CONFIG, RequestHandler)
        logging.info('Server is ready: %s:%s' %SERVER_CONFIG)
        while not __shutdown:
            try:
                l = log_file
                server.handle_request()
            except select.error:
                # do not abort when we receive a signal
                if l == log_file:
                    raise

            if len(sys.argv) > 1:
                break

    elif INTERFACE == 'amqp':
        from .amqp_interface import *

        logging.info('Starting AMQP interface of TAT')
        ## AMQP CONNECTION ##
        start_amqp_interface()

