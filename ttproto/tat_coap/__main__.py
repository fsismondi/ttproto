"""
Invokes webserver to be run at 127.0.0.1:2080 if INTERFACE is amqp,
else runs amqp interface
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
INTERFACE = 'http'
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)


if __name__ == "__main__":

    __shutdown = False

    def shutdown():
        global __shutdown
        __shutdown = True

    for d in TMPDIR, DATADIR, LOGDIR:
        try:
            os.makedirs(d)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise


    if INTERFACE == 'http':
        from .webserver import *

        server = http.server.HTTPServer(SERVER_CONFIG, RequestHandler)
        logging.info('Server is ready: %s:%s' %SERVER_CONFIG)

        while not __shutdown:
            try:
                server.handle_request()
            except Exception as e:
                logging.error(str(e))

            if len(sys.argv) > 1:
                break

    elif INTERFACE == 'amqp':
        from .amqp_interface import *

        logging.info('Starting AMQP interface of TAT')
        ## AMQP CONNECTION ##
        start_amqp_interface()

