"""
Invokes webserver to be run at 127.0.0.1:2080 if INTERFACE is amqp,
else runs amqp interface
Should be run as: python3 -m ttproto.tat_coap
"""
import argparse, os
from ttproto.tat_amqp_interface import *
from ttproto.utils.rmq_handler import JsonFormatter, RabbitMQHandler
from ttproto.tat_coap.webserver import *

# TTPROTO CONSTANTS
COMPONENT_ID = 'tat'
SERVER_CONFIG = ("0.0.0.0", 2080)

# default handler
logger = logging.getLogger(__name__)
sh = logging.StreamHandler()
logger.addHandler(sh)

PCAP_DUMPER_AMQP_TOPICS = ['data.serial.fromAgent.coap_client_agent',
                           'data.serial.fromAgent.coap_server_agent',
                           'data.tun.fromAgent.coap_server_agent',
                           'data.tun.fromAgent.coap_client_agent',
                           ]


def main(argv):
    # parse arguments
    parser = argparse.ArgumentParser(description='Interface for TTProto.')
    parser.add_argument("-i", "--interface",
                        choices=["amqp", "http"],
                        default="amqp",
                        help="Choose the interface.")
    parser.add_argument("-p", "--protocol",
                        choices=["coap", "6lowpan"],
                        help="Choose the protocol to be analyzed by the TAT.",
                        default='coap',
                        )
    parser.add_argument("-d", "--dissector",
                        action='store_true',
                        default=False,
                        help="Launches the dissector component which listens to AMQP bus, "
                             "dissects all exchanged frames and pushes results back into the bus")
    parser.add_argument("-s", "--dumps",
                        action='store_true',
                        default=False,
                        help="Launches a component which listens to data plane in AMQP bus and dumps traces to pcap "
                             "file. --dissector flag auto enables this mode.")

    args = parser.parse_args()

    tat_interface = args.interface
    tat_protocol = args.protocol
    dissector_option = args.dissector
    dumps_option = args.dumps

    if dissector_option:  # auto dissection needs the traces in pcap files
        dumps_option = True

    print('Configuration: interface %s, protocol %s, dissection option %s'
          % (tat_interface, tat_protocol, dissector_option))

    if tat_interface == 'http':
        raise NotImplementedError

    __shutdown = False

    def shutdown():
        global __shutdown
        __shutdown = True

    if tat_interface == 'http':

        server = http.server.HTTPServer(SERVER_CONFIG, RequestHandler)
        logger.info('Server is ready: %s:%s' % SERVER_CONFIG)

        while not __shutdown:
            try:
                server.handle_request()
            except Exception as e:
                logger.error(str(e))

    elif tat_interface == 'amqp':

        # AMQP ENV variables (either get them all from ENV or set them all as default)
        try:
            amqp_exchange = str(os.environ['AMQP_EXCHANGE'])
        except KeyError:
            logger.warning('Cannot retrieve environment variables for AMQP connection. Loading defaults..')
            amqp_exchange = "amq.topic"

        try:
            amqp_url = str(os.environ['AMQP_URL'])
        except KeyError:
            logger.warning('Cannot retrieve environment variables for AMQP connection. Loading defaults..')
            amqp_url = "amqp://local:{1}@{2}/{3}".format('guest', 'guest', 'localhost', '')

        logger.info('Env vars for AMQP connection succesfully imported: AMQP_URL: %s, AMQP_EXCHANGE: %s' % (amqp_url,
                                                                                                      amqp_exchange))

        # AMQP log handler & formatter
        rabbitmq_handler = RabbitMQHandler(amqp_url, COMPONENT_ID)
        json_formatter = JsonFormatter()
        rabbitmq_handler.setFormatter(json_formatter)
        logger.addHandler(rabbitmq_handler)
        logger.setLevel(logging.INFO)

        logger.info('Starting AMQP interface of TAT')

        # launch process: TAT
        p_tat = Process(target=launch_tat_amqp_interface,
                        args=(amqp_url, amqp_exchange, tat_protocol, dissector_option,))
        p_tat.start()

        # launch process: pcap dumper
        if dumps_option or dissector_option:  # dissector component needs dumper
            logger.info('Starting AMQP data plane to pcap dumper')
            p_dumper = Process(target=amqp_data_packet_dumper,
                               args=(amqp_url, amqp_exchange, PCAP_DUMPER_AMQP_TOPICS, TMPDIR,))
            p_dumper.start()


if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
    main(sys.argv[1:])
