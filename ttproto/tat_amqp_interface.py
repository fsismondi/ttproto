#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  (c) 2012  Universite de Rennes 1
#
# Contact address: <t3devkit@irisa.fr>
#
#
# This software is governed by the CeCILL license under French law and
# abiding by the rules of distribution of free software.  You can  use,
# modify and/or redistribute the software under the terms of the CeCILL
# license as circulated by CEA, CNRS and INRIA at the following URL
# "http://www.cecill.info".
#
# As a counterpart to the access to the source code and  rights to copy,
# modify and redistribute granted by the license, users are provided only
# with a limited warranty  and the software's author,  the holder of the
# economic rights,  and the successive licensors  have only  limited
# liability.
#
# In this respect, the user's attention is drawn to the risks associated
# with loading,  using,  modifying and/or developing or reproducing the
# software by the user in light of its specific status of free software,
# that may mean  that it is complicated to manipulate,  and  that  also
# therefore means  that it is reserved for developers  and  experienced
# professionals having in-depth computer knowledge. Users are therefore
# encouraged to load and test the software's suitability as regards their
# requirements in conditions enabling the security of their systems and/or
# data to be ensured and,  more generally, to use and operate it in the
# same conditions as regards security.
#
# The fact that you are presently reading this means that you have had
# knowledge of the CeCILL license and that you accept its terms.

import base64
import pika
import time
import hashlib
import json
import errno
import os
import sys
import uuid
import signal
import logging

from collections import OrderedDict

# Directories
from ttproto import DATADIR
from ttproto import TMPDIR
from ttproto import LOGDIR

from ttproto import LOG_LEVEL
from ttproto.tat_services import analyze_capture, dissect_capture, get_test_cases, base64_to_pcap_file

from ttproto.core.typecheck import typecheck, optional, either
from ttproto.utils import pure_pcapy
from ttproto.utils.rmq_handler import AMQP_URL, AMQP_EXCHANGE, JsonFormatter, RabbitMQHandler
from ttproto.utils import messages
from ttproto.utils.packet_dumper import launch_amqp_data_to_pcap_dumper, AmqpDataPacketDumper
from ttproto.utils import event_bus_utils

COMPONENT_ID = NotImplementedError

AUTO_DISSECT_OUTPUT_FILE = os.path.join(DATADIR, 'auto_dissection')

# Prefix and suffix for the hashes
HASH_PREFIX = 'tt'
HASH_SUFFIX = 'proto'
TOKEN_LENGTH = 28

# states
previous_frames_count = 0

logger = logging.getLogger(__name__)


#####################


def launch_tat_amqp_interface(amqp_url, amqp_exchange, tat_protocol, dissection_auto):
    """
    Att this is blocking. Launches the TAT AMQP interface.
    See doc for more info about the AMQP API endpoints
    """

    def signal_int_handler(self, frame):
        print('got SIGINT, stopping dumper..')

        if amqp_interface:
            amqp_interface.stop()

    signal.signal(signal.SIGINT, signal_int_handler)
    amqp_interface = AmqpInterface(amqp_url, amqp_exchange, tat_protocol, dissection_auto)
    amqp_interface.run()


class AmqpInterface:
    def __init__(self, amqp_url, amqp_exchange, tat_protocol, dissection_auto):
        self.COMPONENT_ID = 'tat|amqp_interface'
        self.tat_protocol = tat_protocol
        self.dissection_auto = dissection_auto

        self.logger = logging.getLogger(self.COMPONENT_ID)
        self.logger.setLevel(LOG_LEVEL)

        # AMQP log handler & formatter
        rabbitmq_handler = RabbitMQHandler(AMQP_URL, self.COMPONENT_ID)
        json_formatter = JsonFormatter()
        rabbitmq_handler.setFormatter(json_formatter)
        self.logger.addHandler(rabbitmq_handler)

        self.amqp_url = amqp_url
        self.amqp_exchange = amqp_exchange
        self.connection = pika.BlockingConnection(pika.URLParameters(self.amqp_url))
        self.channel = self.connection.channel()

        # init AMQP BUS communication vars

        self.services_queue_name = 'services_queue@%s' % self.COMPONENT_ID
        self.channel.queue_declare(queue=self.services_queue_name,
                                   auto_delete=True,
                                   arguments={'x-max-length': 100})

        # subscribe to analysis services requests
        self.channel.queue_bind(exchange=AMQP_EXCHANGE,
                                queue=self.services_queue_name,
                                routing_key=messages.MsgInteropTestCaseAnalyze.routing_key)

        # subscribe to dissection services requests
        self.channel.queue_bind(exchange=AMQP_EXCHANGE,
                                queue=self.services_queue_name,
                                routing_key=messages.MsgDissectionDissectCapture.routing_key)

        self.channel.basic_qos(prefetch_count=1)
        self.channel.basic_consume(self.on_service_request, queue=self.services_queue_name)

        if self.dissection_auto:
            self.data_queue_name = 'data_plane_messages@%s' % self.COMPONENT_ID
            self.channel.queue_declare(queue=self.data_queue_name,
                                       auto_delete=True,
                                       arguments={'x-max-length': 100})

            self.channel.basic_qos(prefetch_count=1)
            self.channel.basic_consume(self.on_data_received, queue=self.data_queue_name)

            # subscribe to data events just to check if there's activity in the data plane
            self.channel.queue_bind(exchange=AMQP_EXCHANGE,
                                    queue=self.data_queue_name,
                                    routing_key='fromAgent.#.packet.raw')

    def run(self):
        # let's send bootstrap message (analysis)
        event_bus_utils.publish_message(
            self.connection,
            messages.MsgTestingToolComponentReady(component='analysis')
        )

        #  let's send bootstrap message (dissector)
        event_bus_utils.publish_message(
            self.connection,
            messages.MsgTestingToolComponentReady(component='dissection')
        )

        # start main job (the following is a blocking call)

        self.logger.info("Awaiting for analysis & dissection requests")
        self.channel.start_consuming()

    def stop(self):

        # FINISHING... let's send a goodby message
        if self.channel is None:
            self.channel = self.connection.channel()

        # dissection shutdown message
        event_bus_utils.publish_message(
            self.connection,
            messages.MsgTestingToolComponentShutdown(component='dissection')
        )

        # analysis shutdown message
        event_bus_utils.publish_message(
            self.connection,
            messages.MsgTestingToolComponentShutdown(component='analysis')
        )

        self.connection.close()

        self.logger.info('Stopping.. Bye bye!')

        sys.exit(0)

    def on_data_received(self, ch, method, props, body):
        global previous_frames_count
        ch.basic_ack(delivery_tag=method.delivery_tag)

        try:
            event_received = messages.Message.load_from_pika(method, props, body)
        except Exception as e:
            self.logger.error(str(e))
            return

        if isinstance(event_received, messages.MsgPacketSniffedRaw):

            try:
                if 'serial' in event_received.interface_name:
                    pcap_to_dissect = os.path.join(AmqpDataPacketDumper.DEFAULT_DUMP_DIR,
                                                   AmqpDataPacketDumper.DEFAULT_802154_DUMP_FILENAME
                                                   )
                elif 'tun' in event_received.interface_name:
                    pcap_to_dissect = os.path.join(AmqpDataPacketDumper.DEFAULT_DUMP_DIR,
                                                   AmqpDataPacketDumper.DEFAULT_RAWIP_DUMP_FILENAME
                                                   )
                else:
                    self.logger.error('Not implemented protocol dissection for %s' % event_received.interface_name)
                    return

                self.logger.info("Data plane activity")

                # note : the sniffing and pcap generation is handled by another process (packet dumper component)
                ch.queue_purge(queue=self.data_queue_name)

                dissection_structured_text, dissection_simple_text = dissect_capture(
                    filename=pcap_to_dissect,
                    proto_filter=None,
                    output_filename=AUTO_DISSECT_OUTPUT_FILE,
                    number_of_frames_to_skip=previous_frames_count
                )
                previous_frames_count += len(dissection_structured_text)

            except (TypeError, pure_pcapy.PcapError) as e:
                self.logger.error("Error processing PCAP: %s" % e)
                return

            except Exception as e:
                self.logger.error(str(e))
                return

            # prepare response with dissection info:
            event_diss = messages.MsgDissectionAutoDissect(
                token=None,
                frames=dissection_structured_text,
                frames_simple_text=dissection_simple_text,
                testcase_id=None,
                testcase_ref=None,
            )
            event_bus_utils.publish_message(self.connection, event_diss)
            self.logger.info("Auto dissection message sent (%s frames).. " % len(dissection_structured_text))

            return

        else:
            self.logger.debug('Unknonwn message. Message dropped: %s' % event_received)

    def on_service_request(self, ch, method, props, body):
        ch.basic_ack(delivery_tag=method.delivery_tag)

        try:
            service_request = messages.Message.load_from_pika(method, props, body)
        except Exception as e:
            self.logger.error(str(e))
            return

        if isinstance(service_request, messages.MsgInteropTestCaseAnalyze):
            self.logger.debug("Starting analysis of PCAP")

            # generation of token
            operation_token = _get_token()

            try:
                pcap_file_base64 = service_request.value
                filename = service_request.filename
                testcase_id = service_request.testcase_id
                testcase_ref = service_request.testcase_ref
                protocol = self.tat_protocol
                if hasattr(service_request, 'protocol') and service_request.protocol is not None:
                    protocol = service_request.protocol

                nb = base64_to_pcap_file(os.path.join(TMPDIR, filename), pcap_file_base64)

                # if pcap file has less than 24 bytes then its an empty pcap file
                if (nb <= 24):
                    event_bus_utils.publish_message(
                        self.connection,
                        messages.MsgErrorReply(
                            service_request,
                            ok=False,
                            error_code=400,
                            error_message='Empty PCAP file received'
                        )
                    )
                    self.logger.warning("Empty PCAP received")
                    return
                else:
                    self.logger.info("Pcap correctly saved %d B at %s" % (nb, os.path.join(TMPDIR, filename)))

                # run the analysis
                analysis_results = analyze_capture(
                    filename=os.path.join(TMPDIR, filename),
                    testcase_id=testcase_id,
                    protocol=protocol,
                    output_filename=os.path.join(DATADIR, operation_token),
                )

            except Exception as e:
                event_bus_utils.publish_message(
                    self.connection,
                    messages.MsgErrorReply(
                        service_request,
                        error_message=str(e)
                    )
                )
                self.logger.error(e)
                self.logger.error(type(e))
                return

            # let's prepare the message
            try:
                response = messages.MsgInteropTestCaseAnalyzeReply(
                    service_request,
                    ok=True,
                    verdict=analysis_results[1],
                    description=analysis_results[3],
                    review_frames=analysis_results[2],
                    partial_verdicts=analysis_results[4],
                    token=operation_token,
                    testcase_id=testcase_id,
                    testcase_ref=testcase_ref
                )
                # send response
                event_bus_utils.publish_message(self.connection, response)
                self.logger.info("Analysis response sent")

            except Exception as e:
                event_bus_utils.publish_message(
                    self.connection,
                    messages.MsgErrorReply(
                        service_request,
                        error_message=str(e)
                    )
                )
                self.logger.error(str(e))
                return

        elif isinstance(service_request, messages.MsgTestSuiteGetTestCases):
            self.logger.warning("API call not implemented. Test coordinator provides this service.")
            return

            # # Get the list of test cases
            # try:
            #     test_cases = get_test_cases()
            #
            #     # lets prepare content of response
            #     tc_list = []
            #     for tc in test_cases:
            #         tc_list.append(test_cases[tc]['tc_basic'])
            #     #TODO build & send response
            # except FileNotFoundError as fnfe:
            #     _publish_message(
            #             ch,
            #             amqp_messages.MsgErrorReply(ok=False, error_message='File not found error')
            #     )
            #     self.logger.error('Cannot fetch test cases list:\n' + str(fnfe))
            #     return

        elif isinstance(service_request, messages.MsgDissectionDissectCapture):
            self.logger.info("Starting dissection of PCAP ...")
            self.logger.info("Decoding PCAP file using base64 ...")

            # get dissect params from request
            pcap_file_base64 = service_request.value
            filename = service_request.filename
            proto_filter = service_request.protocol_selection

            # save pcap as file
            nb = base64_to_pcap_file(os.path.join(TMPDIR, filename), pcap_file_base64)

            # if pcap file has less than 24 bytes then its an empty pcap file
            if (nb <= 24):
                event_bus_utils.publish_message(
                    self.connection,
                    messages.MsgErrorReply(
                        service_request,
                        error_code=400,
                        error_message='Empty PCAP file received'
                    )
                )
                self.logger.warning("Empty PCAP received")
                return

            else:
                self.logger.info("Pcap correctly saved %d B at %s" % (nb, TMPDIR))

            # Lets dissect
            try:
                operation_token = _get_token()
                dissection_structured_text, dissection_simple_text = dissect_capture(
                    filename=os.path.join(TMPDIR, filename),
                    proto_filter=proto_filter,
                    output_filename=os.path.join(DATADIR, operation_token),
                )
            except (TypeError, pure_pcapy.PcapError) as e:
                event_bus_utils.publish_message(
                    self.connection,
                    messages.MsgErrorReply(
                        service_request,
                        error_message="Error processing PCAP. Error: %s" % str(e)
                    )
                )
                self.logger.error("Error processing PCAP: %s" % e)
                return
            except Exception as e:
                event_bus_utils.publish_message(
                    self.connection,
                    messages.MsgErrorReply(
                        service_request,
                        error_message="Error found while dissecting pcap. Error: %s" % str(e)
                    )
                )
                self.logger.error(str(e))
                return

            # prepare response with dissection info:
            response = messages.MsgDissectionDissectCaptureReply(
                service_request,
                token=operation_token,
                frames=dissection_structured_text,
                frames_simple_text=dissection_simple_text
            )
            event_bus_utils.publish_message(self.connection, response)
            return

        else:
            self.logger.warning('Coudnt process the service request: %s' % service_request)
            return


# # # AUXILIARY FUNCTIONS # # #

def _auto_dissect_service():
    global AUTO_DISSECT_PERIOD
    last_polled_pcap = None

    # setup process own connection
    connection = pika.BlockingConnection(pika.URLParameters(AMQP_URL))

    while True:
        time.sleep(AUTO_DISSECT_PERIOD)

        logger.debug('Entering auto triggered dissection process')

        # request to sniffing component
        try:
            request = messages.MsgSniffingGetCaptureLast()
            response = event_bus_utils.amqp_request(connection, request, COMPONENT_ID, use_message_typing=True)

        except event_bus_utils.AmqpSynchCallTimeoutError as amqp_err:
            logger.error(
                'Sniffer didnt respond to Request: %s . Error: %s'
                % (
                    type(request),
                    str(amqp_err)
                )
            )
            return

        if response.ok is False:
            logger.error(
                'Sniffing component coundlt process the %s request correcly, response: %s'
                % (
                    type(request),
                    repr(request)
                )
            )
        else:
            if last_polled_pcap and last_polled_pcap == response.value:
                logger.debug('No new sniffed packets to dissect')
            else:
                logger.debug("Starting auto triggered dissection.")

                # get dissect params from request
                pcap_file_base64 = response.value
                filename = response.filename
                proto_filter = None

                last_polled_pcap = pcap_file_base64

                # save pcap as file
                nb = base64_to_pcap_file(os.path.join(TMPDIR, filename), pcap_file_base64)

                # if pcap file has less than 24 bytes then its an empty pcap file
                if (nb <= 24):
                    logger.warning("Empty PCAP received received.")

                else:
                    logger.info("Pcap correctly saved %d B at %s" % (nb, TMPDIR))

                    # let's dissect
                    try:
                        operation_token = _get_token()
                        dissection_structured_text, dissection_simple_text = dissect_capture(
                            filename=os.path.join(TMPDIR, filename),
                            proto_filter=proto_filter,
                            output_filename=os.path.join(DATADIR, operation_token)
                        )
                    except (TypeError, pure_pcapy.PcapError) as e:
                        logger.error("Error processing PCAP. More: %s" % str(e))
                        return
                    except Exception as e:
                        logger.error("Error while dissecting. Error: %s" % str(e))
                        return

                    # lets create and push the message to the bus
                    m = messages.MsgDissectionAutoDissect(
                        token=operation_token,
                        frames=dissection_structured_text,
                        frames_simple_text=dissection_simple_text,
                        testcase_id=filename.strip('.pcap'),  # dirty solution but less coding :)
                        testcase_ref=None,
                    )
                    event_bus_utils.publish_message(connection, m)


@typecheck
def _get_token(tok: optional(str) = None):
    """
    Function to get a token, if there's a valid one entered just return it
    otherwise generate a new one

    :param tok: The token if there's already one
    :type tok: str

    :return: A token, the same if there's already one, a new one otherwise
    :rtype: str
    """

    # If the token is already a correct one
    try:
        if all((
                tok,
                type(tok) == str,
                len(tok) == 28,
                base64.urlsafe_b64decode(tok + '=')  # Add '=' only for checking
        )):
            return tok
    except:  # If the decode throw an error => Wrong base64
        pass

    # Generate a token
    token = hashlib.sha1(
        str.encode((
            "%s%04d%s" %
            (
                HASH_PREFIX,
                time.time(),
                HASH_SUFFIX
            )
        ), encoding='utf-8')
    )
    token = base64.urlsafe_b64encode(token.digest()).decode()

    # Remove the '=' at the end of it, it is used by base64 for padding
    return token.replace('=', '')
