#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import logging
import argparse
from ttproto import LOG_LEVEL
from ttproto.tat_services import dissect_capture, analyze_capture, get_protocols_list, ALLOWED_PROTOCOLS_FOR_ANALYSIS
from multiprocessing import Process


PCAP_DUMPER_AMQP_TOPICS = [
    'fromAgent.#.packet.raw'
    'data.*.fromAgent.*',  # fixme deprecate this (old API)
]

cli_help = '''ttproto <command> [<args>]

TTProto CLI accepts the following commands:
    dissect         Dissects network traces (.pcap file).
    analyze         Analyses network traces (.pcap file).
    service_amqp    Launches TTProto as an AMQP service.
    service_http    Launches TTProto as a HTTP service (WIP).
'''
diss_help = ''' ttproto dissect file [<options>]

Dissection usage examples:
    dissect ./tests/test_dumps/6lowpan_hc/TD_6LOWPAN_HC_01.pcap
    dissect ./tests/test_dumps/6lowpan_hc/TD_6LOWPAN_HC_01.pcap -o /tmp/dissection.json
    dissect ./tests/test_dumps/6lowpan_hc/TD_6LOWPAN_HC_01.pcap -p sixlowpan
    dissect ./tests/test_dumps/6lowpan_hc/TD_6LOWPAN_HC_01.pcap -p icmpv6
    dissect ./tests/test_dumps/6lowpan_hc/TD_6LOWPAN_HC_01.pcap -p icmpv6echorequest

'''
ana_help = '''ttproto analyze file [<options>]

Analyze usage examples:
    analyze ./tests/test_dumps/6lowpan_hc/TD_6LOWPAN_HC_01.pcap -p 6lowpan -tc TD_6LOWPAN_HC_01 
    analyze ./tests/test_dumps/coap_core/TD_COAP_CORE_01_PASS.pcap -p coap -tc TD_COAP_CORE_01
'''

# TTPROTO CONSTANTS
COMPONENT_ID = 'tat|main'
SERVER_CONFIG = ("0.0.0.0", 2080)

# default handler
logger = logging.getLogger(COMPONENT_ID)
logger.setLevel(LOG_LEVEL)

class TTProtoCLI():
    def __init__(self):
        parser = argparse.ArgumentParser(
            description='Interface for TTProto.',
            usage=cli_help
        )
        parser.add_argument('command', help='Subcommand to run')
        # parse_args defaults to [1:] for args, but you need to
        # exclude the rest of the args too, or validation will fail
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            logging.error('Unrecognized command')
            parser.print_help()
            exit(1)
        # use dispatch pattern to invoke method with same name
        getattr(self, args.command)()

    def dissect(self):
        # parse arguments
        parser = argparse.ArgumentParser(
            description=dissect_capture.__doc__,
            usage=diss_help
        )
        parser.add_argument('file',
                            help="Filename (complete path) to traces file (.pcap file).",
                            )
        parser.add_argument("-p", "--protocol",
                            choices=[i.lower() for i in get_protocols_list()],
                            help="Choose a filter protocol",
                            )
        parser.add_argument("-o", "--output",
                            help="Output file name",
                            default='dissection.json',
                            )

        try:
            args = parser.parse_args(sys.argv[2:])
        except Exception as e:
            print(e)
            parser.print_help()
            exit(1)

        _, disects_as_list_of_text = dissect_capture(
            filename=args.file,
            proto_filter=args.protocol,
            output_filename=args.output
        )

        if disects_as_list_of_text:
            for item in disects_as_list_of_text:
                logger.info(item)
                # print(item.encode('utf-8').decode('unicode_escape')) this doesnt work very well for some bytes

    def analyze(self):
        # parse arguments
        parser = argparse.ArgumentParser(
            description=analyze_capture.__doc__,
            usage=ana_help,
        )

        parser.add_argument('file',
                            help="Filename (complete path) to traces file (.pcap file).",
                            )
        parser.add_argument("-p", "--protocol",
                            choices=ALLOWED_PROTOCOLS_FOR_ANALYSIS,
                            help="Choose the protocol to be analyzed by the TAT.",
                            default='coap',
                            )
        parser.add_argument("-tc", "--test-case",
                            help="Indicate the particular test case ID to check."
                            )
        parser.add_argument("-o", "--output",
                            help="Output file name",
                            default='analysis.json',
                            )
        try:
            args = parser.parse_args(sys.argv[2:])
        except Exception as e:
            print(e)
            parser.print_help()
            exit(1)

        analysis_results = analyze_capture(
            filename=args.file,
            protocol=args.protocol,
            testcase_id=args.test_case,
            output_filename=args.output
        )

        if analysis_results:
            logger.info('result: %s' % analysis_results[1])
            logger.info('details: \n%s' % analysis_results[3])

    def service_http(self):
        raise NotImplementedError

        # from ttproto.tat_coap.webserver import http, RequestHandler
        # __shutdown = False
        #
        # def shutdown():
        #     global __shutdown
        #     __shutdown = True
        #
        # server = http.server.HTTPServer(SERVER_CONFIG, RequestHandler)
        # logger.info('Server is ready: %s:%s' % SERVER_CONFIG)
        #
        # while not __shutdown:
        #     try:
        #         server.handle_request()
        #     except Exception as e:
        #         logger.error(str(e))

    def service_amqp(self):

        from ttproto.tat_amqp_interface import launch_tat_amqp_interface, TMPDIR
        from ttproto.utils.packet_dumper import launch_amqp_data_to_pcap_dumper
        from ttproto.utils.rmq_handler import JsonFormatter, RabbitMQHandler

        # parse arguments
        parser = argparse.ArgumentParser(description='Launches TTProto as an AMQP service.')

        parser.add_argument("-p", "--protocol",
                            choices=ALLOWED_PROTOCOLS_FOR_ANALYSIS,
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
                            help="Launches a component which listens to data plane in AMQP bus and dumps traces to "
                                 "pcap file. --dissector flag auto enables this mode.")

        args = parser.parse_args(sys.argv[2:])

        tat_interface = 'AMQP'
        tat_protocol = args.protocol
        dissector_option = args.dissector
        dumps_option = args.dumps

        if dissector_option:  # auto dissection needs the traces in pcap files
            dumps_option = True

        logger.info('Configuration: \n\tinterface: %s\n\tprotocol: %s \n\tauto-dissection option: %s'
                    % (tat_interface, tat_protocol, dissector_option))

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
                        args=(amqp_url, amqp_exchange, tat_protocol, dissector_option))
        p_tat.start()

        # launch process: pcap dumper
        if dumps_option or dissector_option:  # dissector component needs dumper
            logger.info('Starting AMQP data plane to pcap dumper')
            p_dumper = Process(
                target=launch_amqp_data_to_pcap_dumper(),
                args=(amqp_url, amqp_exchange, PCAP_DUMPER_AMQP_TOPICS, TMPDIR)
            )
            p_dumper.start()


if __name__ == '__main__':
    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
    TTProtoCLI()
