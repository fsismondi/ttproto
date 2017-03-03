"""
Invokes webserver to be run at 127.0.0.1:2080 if INTERFACE is amqp,
else runs amqp interface
Should be run as: python3 -m ttproto.tat_coap
"""
import select
import signal
import os
import errno
import logging
from ttproto import *
from ttproto.utils.rmq_handler import AMQP_URL, JsonFormatter, RabbitMQHandler

# TTPROTO CONSTANTS
COMPONENT_ID = 'tat'

# Directories
DATADIR = "data"
TMPDIR = "tmp"
LOGDIR = "log"

SERVER_CONFIG = ("0.0.0.0", 2080)
# either amqp (amqp interface) or http (webserver)
INTERFACE = 'amqp'

# default handler
logger = logging.getLogger(__name__)
sh = logging.StreamHandler()
logger.addHandler(sh)


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
        logger.info('Server is ready: %s:%s' %SERVER_CONFIG)

        while not __shutdown:
            try:
                server.handle_request()
            except Exception as e:
                logger.error(str(e))

            if len(sys.argv) > 1:
                break

    elif INTERFACE == 'amqp':
        from .amqp_interface import *

        logger.info('TAT starting..')

        # use F-Interop logger handler & formatter
        rabbitmq_handler = RabbitMQHandler(AMQP_URL, COMPONENT_ID)
        json_formatter = JsonFormatter()
        rabbitmq_handler.setFormatter(json_formatter)
        logger.addHandler(rabbitmq_handler)
        logger.setLevel(logging.DEBUG)

        logger.info('Starting AMQP interface of TAT')
        ## AMQP CONNECTION ##
        start_amqp_interface()

