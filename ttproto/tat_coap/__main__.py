"""
Invokes webserver to be run at 127.0.0.1:2080 if INTERFACE is amqp,
else runs amqp interface
Should be run as: python3 -m ttproto.tat_coap
"""
import select
import signal
import os
import errno
import sys
import logging
import argparse
from .webserver import *
from .amqp_interface import *
from ttproto import *
from ttproto.utils.rmq_handler import AMQP_URL, JsonFormatter, RabbitMQHandler

# TTPROTO CONSTANTS
COMPONENT_ID = 'tat'

SERVER_CONFIG = ("0.0.0.0", 2080)

# default handler
logger = logging.getLogger(__name__)
sh = logging.StreamHandler()
logger.addHandler(sh)


def main(argv):
    # Add argument with argparse to choose the interface
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", choices=["amqp", "http"],
                        help="Choose the interface by default it\'s http")
    args = parser.parse_args()
    if args.interface == "amqp":
        INTERFACE = 'amqp'
        print("Interface is amqp")
    elif args.interface == "http":
        INTERFACE = 'http'
        print("Interface is http")
    else:
        # either amqp (amqp interface) or http (webserver)
        print("Interface is http")
        INTERFACE = 'http'

    __shutdown = False

    def shutdown():
        global __shutdown
        __shutdown = True

    if INTERFACE == 'http':

        server = http.server.HTTPServer(SERVER_CONFIG, RequestHandler)
        logger.info('Server is ready: %s:%s' % SERVER_CONFIG)

        while not __shutdown:
            try:
                server.handle_request()
            except Exception as e:
                logger.error(str(e))


    elif INTERFACE == 'amqp':

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


if __name__ == "__main__":
    main(sys.argv[1:])
