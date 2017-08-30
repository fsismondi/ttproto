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
import time, hashlib
import json, errno, os, sys
import uuid
import signal
import logging

from collections import OrderedDict
from multiprocessing import Process
from ttproto.core.analyzer import Analyzer
from ttproto.core.dissector import Dissector
from ttproto.core.typecheck import typecheck, optional, either
from ttproto.utils import pure_pcapy
from ttproto.core.lib.all import *
from ttproto.utils.rmq_handler import AMQP_URL, AMQP_EXCHANGE, JsonFormatter, RabbitMQHandler
from ttproto.utils import amqp_messages
from ttproto.utils.packet_dumper import launch_amqp_data_to_pcap_dumper, AmqpDataPacketDumper

COMPONENT_ID = NotImplementedError

ALLOWED_EXTENSIONS = set(['pcap'])
ALLOWED_PROTOCOLS_FOR_ANALYSIS = ['coap', '6lowpan']

# Directories
DATADIR = "data"
TMPDIR = "tmp"
LOGDIR = "log"
AUTO_DISSECT_OUTPUT_FILE = 'auto_dissection'

# Prefix and suffix for the hashes
HASH_PREFIX = 'tt'
HASH_SUFFIX = 'proto'
TOKEN_LENGTH = 28

# lower versbosity of pika's logs
logging.getLogger('pika').setLevel(logging.INFO)

logger = logging.getLogger(__name__)


#####################


def launch_tat_amqp_interface(amqp_url, amqp_exchange, tat_protocol, dissection_auto):
    def signal_int_handler(self, frame):
        logger.info('got SIGINT, stopping dumper..')

        if amqp_interface:
            amqp_interface.stop()

    signal.signal(signal.SIGINT, signal_int_handler)

    amqp_interface = AmqpInterface(amqp_url, amqp_exchange, tat_protocol, dissection_auto)
    amqp_interface.run()


class AmqpInterface:
    def __init__(self, amqp_url, amqp_exchange, tat_protocol, dissection_auto):
        self.COMPONENT_ID = 'tat'
        self.tat_protocol = tat_protocol
        self.dissection_auto = dissection_auto

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
                                routing_key='control.analysis.service')

        # subscribe to dissection services requests
        self.channel.queue_bind(exchange=AMQP_EXCHANGE,
                                queue=self.services_queue_name,
                                routing_key='control.dissection.service')

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
                                    routing_key='data.#')

    def run(self):
        # let's send bootstrap message (analysis)
        _publish_message(
            self.channel,
            amqp_messages.MsgTestingToolComponentReady(component='analysis')
        )

        #  let's send bootstrap message (dissector)
        _publish_message(
            self.channel,
            amqp_messages.MsgTestingToolComponentReady(component='dissection')
        )

        # start main job (the following is a blocking call)

        logger.info("Awaiting for analysis & dissection requests")
        self.channel.start_consuming()

    def stop(self):

        # FINISHING... let's send a goodby message
        if self.channel is None:
            self.channel = self.connection.channel()

        # dissection shutdown message
        _publish_message(
            self.channel,
            amqp_messages.MsgTestingToolComponentShutdown(component='dissection')
        )

        # analysis shutdown message
        _publish_message(
            self.channel,
            amqp_messages.MsgTestingToolComponentShutdown(component='analysis')
        )

        self.connection.close()

        logger.info('Stopping.. Bye bye!')

        sys.exit(0)

    def on_data_received(self, ch, method, props, body):
        ch.basic_ack(delivery_tag=method.delivery_tag)

        try:
            props_dict = {
                'content_type': props.content_type,
                'delivery_mode': props.delivery_mode,
                'correlation_id': props.correlation_id,
                'reply_to': props.reply_to,
                'message_id': props.message_id,
                'timestamp': props.timestamp,
                'user_id': props.user_id,
                'app_id': props.app_id,
            }
            event_received = amqp_messages.Message.from_json(body)
            event_received.update_properties(**props_dict)

        except Exception as e:
            logger.error(str(e))
            return

        if isinstance(event_received, amqp_messages.MsgPacketSniffedRaw):

            try:

                if 'serial' in event_received.interface_name:
                    pcap_to_dissect = os.path.join(AmqpDataPacketDumper.DEFAULT_DUMP_DIR,
                                                   AmqpDataPacketDumper.DEFAULT_802154_DUMP_FILENAME
                                                   )
                elif 'tun' in event_received.interface_name:
                    pcap_to_dissect = os.path.join(AmqpDataPacketDumper.DEFAULT_DUMP_DIR,
                                                   AmqpDataPacketDumper.DEFAULT_RAWIP_DUMP_FILENAME
                                                   ),
                else:
                    logger.error('Not implemented protocol dissection for %s' % event_received.interface_name)
                    return

                logger.info("Data plane activity")
                # this acts as a filter, we dont want a dissection per message on the bus, we need on for all data messages
                time.sleep(1)
                ch.queue_purge(queue=self.data_queue_name)

                dissection_results = _dissect_capture(
                    filename=pcap_to_dissect,
                    proto_filter=None,
                    output_file=AUTO_DISSECT_OUTPUT_FILE,
                )

            except (TypeError, pure_pcapy.PcapError) as e:
                logger.error("Error processing PCAP")
                return

            except Exception as e:
                logger.error(str(e))
                return

            # prepare response with dissection info:
            event_diss = amqp_messages.MsgDissectionAutoDissect(
                token=None,
                frames=dissection_results,
                testcase_id='unknown',
                testcase_ref='unknown'
            )
            _publish_message(ch, event_diss)
            # logger.info("Auto dissection sent: " + repr(event_diss))
            logger.info("Auto dissection sent.. ")

            return

        else:
            logger.debug('Unknonwn message. Message dropped: %s' % event_received)

    def on_service_request(self, ch, method, props, body):
        ch.basic_ack(delivery_tag=method.delivery_tag)

        try:
            props_dict = {
                'content_type': props.content_type,
                'delivery_mode': props.delivery_mode,
                'correlation_id': props.correlation_id,
                'reply_to': props.reply_to,
                'message_id': props.message_id,
                'timestamp': props.timestamp,
                'user_id': props.user_id,
                'app_id': props.app_id,
            }
            service_request = amqp_messages.Message.from_json(body)
            service_request.update_properties(**props_dict)

        except Exception as e:
            logger.error(str(e))
            return

        if isinstance(service_request, amqp_messages.MsgInteropTestCaseAnalyze):
            logger.debug("Starting analysis of PCAP")

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

                nb = _save_capture(filename, pcap_file_base64)

                # if pcap file has less than 24 bytes then its an empty pcap file
                if (nb <= 24):
                    _publish_message(
                        ch,
                        amqp_messages.MsgErrorReply(
                            service_request,
                            ok=False,
                            error_message='Empty PCAP file received'
                        )
                    )
                    logger.warning("Empty PCAP received")
                    return
                else:
                    logger.info("Pcap correctly saved %d B at %s" % (nb, TMPDIR))

                self.tat_protocol
                # run the analysis
                analysis_results = _analyze_capture(filename=filename,
                                                    testcase_id=testcase_id,
                                                    protocol=protocol,
                                                    output_file=operation_token
                                                    )

            except Exception as e:
                _publish_message(
                    ch,
                    amqp_messages.MsgErrorReply(
                        service_request,
                        error_message=str(e)
                    )
                )
                logger.error(str(e))
                logger.error(e)
                logger.error(type(e))
                logger.error(e.__mro__)
                return

            # let's prepare the message
            try:
                response = amqp_messages.MsgInteropTestCaseAnalyzeReply(
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
                _publish_message(ch, response)
                logger.info("Analysis response sent: " + repr(response))

            except Exception as e:
                _publish_message(
                    ch,
                    amqp_messages.MsgErrorReply(
                        service_request,
                        error_message=str(e)
                    )
                )
                logger.error(str(e))
                return

        elif isinstance(service_request, amqp_messages.MsgTestSuiteGetTestCases):
            logger.warning("API call not implemented. Test coordinator provides this service.")
            return

            # # Get the list of test cases
            # try:
            #     test_cases = _get_test_cases()
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
            #     logger.error('Cannot fetch test cases list:\n' + str(fnfe))
            #     return

        elif isinstance(service_request, amqp_messages.MsgDissectionDissectCapture):
            logger.info("Starting dissection of PCAP ...")
            logger.info("Decoding PCAP file using base64 ...")

            # get dissect params from request
            pcap_file_base64 = service_request.value
            filename = service_request.filename
            proto_filter = service_request.protocol_selection

            # save pcap as file
            nb = _save_capture(filename, pcap_file_base64)

            # if pcap file has less than 24 bytes then its an empty pcap file
            if (nb <= 24):
                _publish_message(
                    ch,
                    amqp_messages.MsgErrorReply(
                        service_request,
                        error_message='Empty PCAP file received'
                    )
                )
                logger.warning("Empty PCAP received")
                return

            else:
                logger.info("Pcap correctly saved %d B at %s" % (nb, TMPDIR))

            # Lets dissect
            operation_token = _get_token()
            try:
                dissection = _dissect_capture(
                    filename,
                    proto_filter,
                    operation_token
                )
            except (TypeError, pure_pcapy.PcapError) as e:
                _publish_message(
                    ch,
                    amqp_messages.MsgErrorReply(
                        service_request,
                        error_message="Error processing PCAP. Error: %s" % str(e)
                    )
                )
                logger.error("Error processing PCAP")
                return
            except Exception as e:
                _publish_message(
                    ch,
                    amqp_messages.MsgErrorReply(
                        service_request,
                        error_message="Error found while dissecting pcap. Error: %s" % str(e)
                    )
                )
                logger.error(str(e))
                return

            # prepare response with dissection info:
            response = amqp_messages.MsgDissectionDissectCaptureReply(
                service_request,
                token=operation_token,
                frames=dissection
            )
            _publish_message(ch, response)
            return

        else:
            logger.warning('Coudnt process the service request: %s' % service_request)
            return


# # # AUXILIARY FUNCTIONS # # #


def _analyze_capture(filename, protocol, testcase_id, output_file):
    assert filename
    assert protocol
    assert testcase_id

    if os.path.isfile(filename) is False and os.path.isfile(os.path.join(TMPDIR, filename)):
        filename = os.path.join(TMPDIR, filename)

    logger.info("Analyzing PCAP file %s" % filename)

    if protocol.lower() not in ALLOWED_PROTOCOLS_FOR_ANALYSIS:
        raise NotImplementedError('Protocol %s not among the allowed analysis test suites' % protocol)

    analysis_results = Analyzer('tat_' + protocol.lower()).analyse(filename, testcase_id)
    logger.info('analysis result: %s' % str(analysis_results))
    logger.debug('PCAP analysed')

    if output_file and type(output_file) is str:
        # save analysis response
        _dump_json_to_file(json.dumps(analysis_results), os.path.join(DATADIR, output_file))

    return analysis_results


def _dissect_capture(filename, proto_filter=None, output_file=None):
    """
    Raises TypeError or pure_pcapy.PcapError if there's an error with the PCAP file
    """
    assert filename

    if os.path.isfile(filename) is False and os.path.isfile(os.path.join(TMPDIR, filename)):
        filename = os.path.join(TMPDIR, filename)

    logger.info("Dissecting PCAP file %s" % filename)
    proto_matched = None

    if proto_filter:
        # In function of the protocol asked
        proto_matched = _get_protocol(proto_filter)
        if proto_matched is None:
            raise Exception('Unknown protocol %s' % proto_filter)

    if proto_matched and len(proto_matched) == 1:
        dissection = Dissector(filename).dissect(eval(proto_matched[0]['name']))
    else:
        dissection = Dissector(filename).dissect()

    logger.info('PCAP dissected')

    if output_file and type(output_file) is str:
        # save dissection response
        _dump_json_to_file(json.dumps(dissection), os.path.join(DATADIR, output_file))

    return dissection


@typecheck
def _get_test_cases(
        testcase_id: optional(str) = None,
        verbose: bool = False
) -> OrderedDict:
    """
    Function to get the implemented test cases

    :param testcase_id: The id of the single test case if one wanted
    :param verbose: True if we want a verbose response
    :type testcase_id: str
    :type verbose: bool

    :return: The implemented test cases using doc.f-interop.eu format
    :rtype: OrderedDict
    """

    test_cases = OrderedDict()
    tc_query = [] if not testcase_id else [testcase_id]
    raw_tcs = Analyzer('tat_coap').get_implemented_testcases(
        tc_query,
        verbose
    )

    # Build the clean results list
    for raw_tc in raw_tcs:
        tc_basic = OrderedDict()
        tc_basic['_type'] = 'tc_basic'
        tc_basic['id'] = raw_tc[0]
        tc_basic['objective'] = raw_tc[1]

        tc_implementation = OrderedDict()
        tc_implementation['_type'] = 'tc_implementation'
        tc_implementation['implementation'] = raw_tc[2]

        # Tuple, basic + implementation
        test_cases[raw_tc[0]] = OrderedDict()
        test_cases[raw_tc[0]]['tc_basic'] = tc_basic
        test_cases[raw_tc[0]]['tc_implementation'] = tc_implementation

    # If a single element is asked
    if testcase_id:
        test_cases = test_cases[raw_tcs[0][0]]

    # Return the results
    return test_cases


def _auto_dissect_service():
    global AUTO_DISSECT_PERIOD
    last_polled_pcap = None

    # setup process own connection and channel
    connection = pika.BlockingConnection(pika.URLParameters(AMQP_URL))
    channel = connection.channel()

    while True:
        time.sleep(AUTO_DISSECT_PERIOD)

        logger.debug('Entering auto triggered dissection process')

        # request to sniffing component
        try:
            request = amqp_messages.MsgSniffingGetCaptureLast()
            response = _amqp_request(channel, request, COMPONENT_ID)

        except TimeoutError as amqp_err:
            logger.error(
                'Sniffer didnt respond to Request: %s . Error: %s'
                % (
                    request._type,
                    str(amqp_err)
                )
            )
            return

        if response.ok is False:
            logger.error(
                'Sniffing component coundlt process the %s request correcly, response: %s'
                % (
                    request._type,
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
                nb = _save_capture(filename, pcap_file_base64)

                # if pcap file has less than 24 bytes then its an empty pcap file
                if (nb <= 24):
                    logger.warning("Empty PCAP received received.")

                else:
                    logger.info("Pcap correctly saved %d B at %s" % (nb, TMPDIR))

                    # let's dissect
                    try:
                        dissection, operation_token = _dissect_capture(filename, proto_filter, None)
                    except (TypeError, pure_pcapy.PcapError) as e:
                        logger.error("Error processing PCAP. More: %s" % str(e))
                        return
                    except Exception as e:
                        logger.error("Error while dissecting. Error: %s" % str(e))
                        return

                    # lets create and push the message to the bus
                    m = amqp_messages.MsgDissectionAutoDissect(
                        token=operation_token,
                        frames=dissection,
                        testcase_id=filename.strip('.pcap'),  # dirty solution but less coding :)
                        testcase_ref='unknown'  # not really needed
                    )
                    _publish_message(channel, m)


def _amqp_request(channel, request_message: Message, component_id: str):
    # NOTE: channel must be a pika channel

    # check first that sender didnt forget about reply to and corr id
    assert request_message.reply_to
    assert request_message.correlation_id

    response = None

    reply_queue_name = 'amqp_rpc_%s@%s' % (str(uuid.uuid4())[:8], component_id)

    result = channel.queue_declare(queue=reply_queue_name,
                                   auto_delete=True,
                                   arguments={'x-max-length': 100})

    callback_queue = result.method.queue

    # bind and listen to reply_to topic
    channel.queue_bind(
        exchange=AMQP_EXCHANGE,
        queue=callback_queue,
        routing_key=request_message.reply_to
    )

    channel.basic_publish(
        exchange=AMQP_EXCHANGE,
        routing_key=request_message.routing_key,
        properties=pika.BasicProperties(**request_message.get_properties()),
        body=request_message.to_json(),
    )

    time.sleep(0.2)
    retries_left = 5

    while retries_left > 0:
        time.sleep(0.5)
        method, props, body = channel.basic_get(reply_queue_name)
        if method:
            channel.basic_ack(method.delivery_tag)
            if hasattr(props, 'correlation_id') and props.correlation_id == request_message.correlation_id:
                break
        retries_left -= 1

    if retries_left > 0:

        body_dict = json.loads(body.decode('utf-8'), object_pairs_hook=OrderedDict)
        response = amqp_messages.MsgReply(request_message, **body_dict)

    else:
        raise TimeoutError(
            "Response timeout! rkey: %s , request type: %s" % (
                request_message.routing_key,
                request_message._type
            )
        )

    # clean up
    channel.queue_delete(reply_queue_name)

    return response


def _publish_message(channel, message):
    """ Published which uses message object metadata

    :param channel:
    :param message:
    :return:
    """

    properties = pika.BasicProperties(**message.get_properties())

    channel.basic_publish(
        exchange=AMQP_EXCHANGE,
        routing_key=message.routing_key,
        properties=properties,
        body=message.to_json(),
    )


@typecheck
def _get_protocol(
        protocol: optional(str) = None
) -> either(list, type(None)):
    """
    Function to get the protocols protocol(s) info dict

    :param protocol: The name of the protocol
    :type protocol: str

    :return: list of implemented protocols, conditioned to the protocol filter
    :rtype: list of OrderedDict(s)
    """

    # list to return
    answer = []

    # Getter of protocol's classes from dissector
    prot_classes = Dissector.get_implemented_protocols()
    logger.debug(str(prot_classes))

    # Build the clean results list
    for prot_class in prot_classes:

        if protocol and protocol.lower() == prot_class.__name__.lower():
            # Prepare the dict for the answer
            prot = OrderedDict()
            prot['_type'] = 'implemented_protocol'
            prot['name'] = prot_class.__name__
            prot['description'] = ''
            return [prot]
        elif protocol is None:
            # Prepare the subdir for the dict-inception (answer)
            prot = OrderedDict()
            prot['_type'] = 'implemented_protocol'
            prot['name'] = prot_class.__name__
            prot['description'] = ''
            answer.append(prot)
        else:
            # not the selected one
            pass

    if answer is None or len(answer) == 0:
        return None
    else:
        return answer


def _dump_json_to_file(json_object, filename):
    """

    :param json_object:
    :param filename: filename must include PATH
    :return:
    """

    if '.json' not in filename:
        filename += '.json'

    with open(filename, 'w') as f:
        f.write(json_object)


def _save_capture(filename, pcap_file_base64):
    """
    Returns number of bytes saved.

    :param filename:
    :param pcap_file_base64:
    :return:
    """
    # save to file
    with open(os.path.join(TMPDIR, filename), "wb") as pcap_file:
        nb = pcap_file.write(base64.b64decode(pcap_file_base64))

        return nb


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


if __name__ == "__main__":
    # print(str(_get_protocol('CoAP')))
    # print(str(_get_protocol()))
    print(str(eval('CoAP')))
    dissection = Dissector(TMPDIR + '/TD_COAP_CORE_02.pcap').dissect()  # eval('CoAP'))
    # dissection = Dissector(TMPDIR + '/tun_sniffed_coap.pcap').dissect(eval('CoAP'))
    print(dissection)