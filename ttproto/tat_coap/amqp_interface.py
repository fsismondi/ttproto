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
from ttproto.utils.rmq_handler import AMQP_URL, JsonFormatter, RabbitMQHandler

COMPONENT_ID = 'tat'
AMQP_EXCHANGE = 'default'
ALLOWED_EXTENSIONS = set(['pcap'])
COMPONENT_DIR = 'ttproto/tat_coap'

# Directories
DATADIR = "data"
TMPDIR = "tmp"
LOGDIR = "log"

# Prefix and suffix for the hashes
HASH_PREFIX = 'tt'
HASH_SUFFIX = 'proto'
TOKEN_LENGTH = 28

# flag that triggers automatic dissection periodically
AUTOMATIC_DISSECTION_ENA = True
# period in seconds
AUTO_DISSECT_PERIOD = 5

#lower versbosity of pika's logs
logging.getLogger('pika').setLevel(logging.INFO)

logger = logging.getLogger(__name__)

#####################

# process for auto polling pcaps and dissecting
process_auto_diss = None

def signal_int_handler(signal, frame):

    connection = pika.BlockingConnection(pika.URLParameters(AMQP_URL))
    channel = connection.channel()

    # FINISHING... let's send a goodby message

    msg = {
        'message': '{component} is out! Bye bye..'.format(component='dissector'),
        "_type": '{component}.shutdown'.format(component='dissection')
    }

    channel.basic_publish(
            body=json.dumps(msg),
            routing_key='control.session.info',
            exchange=AMQP_EXCHANGE,
            properties=pika.BasicProperties(
                    content_type='application/json',
            )
    )
    msg = {
        'message': '{component} is out! Bye bye..'.format(component=COMPONENT_ID),
        "_type": '{component}.shutdown'.format(component='analysis')
    }

    channel.basic_publish(
            body=json.dumps(msg),
            routing_key='control.session.info',
            exchange=AMQP_EXCHANGE,
            properties=pika.BasicProperties(
                    content_type='application/json',
            )
    )

    logger.info('got SIGINT \n Bye bye!')

    sys.exit(0)

signal.signal(signal.SIGINT, signal_int_handler)

def start_amqp_interface():

    connection = pika.BlockingConnection(pika.URLParameters(AMQP_URL))
    channel = connection.channel()

    services_queue_name = 'services_queue@%s' % COMPONENT_ID
    channel.queue_declare(queue=services_queue_name)

    events_queue_name = 'events_queue@%s' % COMPONENT_ID
    channel.queue_declare(queue=events_queue_name)

    # subscribe to analysis services requests
    channel.queue_bind(exchange=AMQP_EXCHANGE,
                       queue=services_queue_name,
                       routing_key='control.analysis.service')

    # subscribe to dissection services requests
    channel.queue_bind(exchange=AMQP_EXCHANGE,
                       queue=services_queue_name,
                       routing_key='control.dissection.service')

    # subscribe to analysis services requests
    channel.queue_bind(exchange=AMQP_EXCHANGE,
                       queue=events_queue_name,
                       routing_key='control.testcoordination')

    #  let's send bootstrap message (tat)
    msg = {
        'message': '{component} is up!'.format(component=COMPONENT_ID),
        "_type": '{component}.ready'.format(component='analysis')
    }

    # Hello world message from tat
    channel.basic_publish(
            body=json.dumps(msg),
            routing_key='control.session.bootstrap',
            exchange=AMQP_EXCHANGE,
            properties=pika.BasicProperties(
                    content_type='application/json',
            )
    )

    #  let's send bootstrap message (dissector)
    msg = {
        'message': '{component} is up!'.format(component='dissection'),
        "_type": '{component}.ready'.format(component='dissection')
    }

    # Hello world message from dissector (api implemented by this component too)
    channel.basic_publish(
            body=json.dumps(msg),
            routing_key='control.session.bootstrap',
            exchange=AMQP_EXCHANGE,
            properties=pika.BasicProperties(
                    content_type='application/json',
            )
    )

    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(on_service_request, queue=services_queue_name)

    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(on_event_received, queue=events_queue_name)

    # STARTING main job( the following is blocking call )
    logger.info("Awaiting for analysis & dissection requests")
    channel.start_consuming()


def on_event_received(ch, method, props, body):

    ch.basic_ack(delivery_tag=method.delivery_tag)

    req_body_dict = json.loads(body.decode('utf-8'))

    try:
        # get type to trigger the right ttproto call
        req_type = req_body_dict['_type']

    except Exception as e:
        logger.error(ch,str(e))
        return

    if req_type == 'testcoordination.testsuite.start':

        logger.info("Test suite started: %s, body: %s" % (str(req_body_dict), str(body)))

        # if automated dissection flag true then launch job as another process
        if AUTOMATIC_DISSECTION_ENA:
            global process_auto_diss
            logger.info("[auto_triggered_dissector] starting second process for automated dissections")
            process_auto_diss = Process(name='auto_triggered_dissector',target=_auto_dissect_service)
            process_auto_diss.start()
    else:
        logger.debug("Event received ignored: %s" % (str(req_body_dict)))

def on_service_request(ch, method, props, body):

    req_body_dict = json.loads(body.decode('utf-8'))
    logger.debug("Service request received: %s, body: %s" %(str(req_body_dict),str(body)))

    try:
        # get type to trigger the right ttproto call
        req_type = req_body_dict['_type']

    except Exception as e:
        logger.error(ch,str(e))

    response = OrderedDict()

    if req_type == 'analysis.testcase.analyze':
        logger.info("Starting analysis of PCAP")
        ch.basic_ack(delivery_tag=method.delivery_tag)
        logger.info("Decoding PCAP file using base64 ...")
        try:
            pcap_file_base64 = req_body_dict['value']
            filename = req_body_dict['filename']
            testcase_id = req_body_dict['testcase_id']
            testcase_ref = req_body_dict['testcase_ref']

            nb = _save_capture(filename,pcap_file_base64)

            # if pcap file has less than 24 bytes then its an empty pcap file
            if (nb <= 24):
                response['_type'] = req_type
                response['ok'] = False
                response['error_message'] = 'Empty PCAP file received'
                response['error_code'] = 'TBD'
                # send the reposnse with ok=false
                _amqp_reply(ch,props,response)
                logger.error("Empty PCAP received")
                return

            else:
                logger.info("Pcap correctly saved %d B at %s" % (nb, TMPDIR))

            # we run the analysis
            analysis_results = Analyzer('tat_coap').analyse(os.path.join(TMPDIR, filename), testcase_id)
            logger.debug('analysis result: %s' %str(analysis_results))

        except Exception as e:
            logger.error(ch,str(e))
            return

            #let's prepare the message
        try:
            response = OrderedDict()
            response['_type'] = 'analysis.testcase.analyze.verdict'
            response['ok'] = True
            response['verdict'] = analysis_results[1]
            # TODO make a description less verborragic -> fix in ttproto.analyse method , not here..
            response['description'] = analysis_results[3]
            response['review_frames'] = analysis_results[2]
            response['partial_verdicts'] = analysis_results[4]
            response['token'] = _get_token()
            response['testcase_id'] = testcase_id
            response['testcase_ref'] = testcase_ref
            logger.info("Analysis response sent: " + str(json.dumps(response)))

        except Exception as e :

            response['_type'] = req_type
            response['ok'] = False
            response['error_message'] = 'str(e)'
            response['error_code'] = 'TBD'
            # send the reposnse with ok=false
            _amqp_reply(ch, props, response)
            logger.error(ch, str(e))
            return

        # send response
        logger.info("Sending test case analysis through the AMQP interface ...")
        _amqp_reply(ch, props, response)

    elif req_type == 'analysis.testsuite.gettestcases':
        logger.info("Getting test cases implemented in TAT ...")
        ch.basic_ack(delivery_tag=method.delivery_tag)

        # Get the list of test cases
        try:
            test_cases = _get_test_cases()
        except FileNotFoundError as fnfe:
            response['_type'] = req_type
            response['ok'] = False
            response['error_message'] = 'Empty PCAP file received'
            response['error_code'] = 'TBD'
            # send the reposnse with ok=false
            _amqp_reply(ch, props, response)

            logger.error(ch,'Cannot fetch test cases list:\n' + str(fnfe))
            return

        # lets prepare content of response
        tc_list = []
        for tc in test_cases:
            tc_list.append(test_cases[tc]['tc_basic'])

        # The result to return
        response['_type'] = req_type
        response['ok'] = True
        response['tc_list'] = tc_list

        #send response
        _amqp_reply(ch,props,response)

    elif req_type == 'dissection.dissectcapture':
        ch.basic_ack(delivery_tag=method.delivery_tag)
        logger.info("Starting dissection of PCAP ...")

        pcap_file_base64 = req_body_dict['value']
        filename = req_body_dict['filename']

        proto_matched = None

        try:
            if 'protocol_selection' in req_body_dict.keys():
                proto_filter = req_body_dict['protocol_selection']

                # Check the protocol_selection value
                if not type(proto_filter) == str:
                    logger.error(ch, 'Expected protocol_selection post value to be a text (eq string)')
                    return

                # In function of the protocol asked
                proto_matched = _get_protocol(proto_filter)
                if proto_matched is None:
                    logger.error(ch, 'Unknown protocol %s' % proto_filter)
                    return

        except Exception as e:
            response['_type'] = req_type
            response['ok'] = False
            response['error_message'] = str(e)
            response['error_code'] = 'TBD'
            # send the reposnse with ok=false
            _amqp_reply(ch, props, response)
            logger.error(ch,str(e))
            return

        logger.info("Decoding PCAP file using base64 ...")

        # save pcap as file
        nb = _save_capture(filename, pcap_file_base64)

        # if pcap file has less than 24 bytes then its an empty pcap file
        if (nb <= 24):
            response['_type'] = req_type
            response['ok'] = False
            response['error_message'] = 'Empty PCAP file received'
            response['error_code'] = 'TBD'
            # send the reposnse with ok=false
            _amqp_reply(ch, props, response)
            logger.error("Empty PCAP received")
            return

        else:
            logger.info("Pcap correctly saved %d B at %s" % (nb, TMPDIR))

        # Lets dissect
        try:
            if proto_matched and len(proto_matched) == 1:
                dissection = Dissector(TMPDIR + '/' + filename).dissect(eval(proto_matched[0]['name']))
            else:
                dissection = Dissector(TMPDIR + '/' + filename).dissect()

            logger.debug('Dissected PCAP: %s' %json.dumps(dissection))

        except (TypeError, pure_pcapy.PcapError) as e:

            response['_type'] = req_type
            response['ok'] = False
            response['error_message'] = str(e)
            response['error_code'] = 'TBD'
            # send the reposnse with ok=false
            _amqp_reply(ch, props, response)
            logger.error("Error processing PCAP")
            logger.error(ch, str(e))
            return

        except:
            response['_type'] = req_type
            response['ok'] = False
            response['error_message'] = str(e)
            response['error_code'] = 'TBD'
            # send the reposnse with ok=false
            _amqp_reply(ch, props, response)
            logger.error(ch, str(e))
            return

        # prepare response with dissection info:
        response = OrderedDict()
        response.update({'_type': req_type})
        response.update({'ok' : True})
        response.update({'token': _get_token()})
        response.update({'frames': dissection})
        _amqp_reply(ch,props,response)

    else:
        logger.warning(ch,'Coulnt process the service request: %s' %str(req_body_dict))

    #finally:
    logger.info("Sending test case analysis through the AMQP interface %s" % json.dumps(response))




### AUXILIARY FUNCTIONS ###

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

    # reques/reply queues configs
    request_r_key= 'control.sniffing.service'
    response_r_key = request_r_key + '.reply'
    request_message_type = 'sniffing.getcapture'


    reply_queue_name = 'auto_triggered_dissection@%s'%COMPONENT_ID

    result = channel.queue_declare(queue=reply_queue_name)
    callback_queue = result.method.queue

    #lets purge in case there are old messages
    channel.queue_purge(reply_queue_name)

    # by convention routing key of answer is routing_key + .reply
    channel.queue_bind(exchange=AMQP_EXCHANGE,
                       queue=callback_queue,
                       routing_key=response_r_key)

    while True:
        time.sleep(AUTO_DISSECT_PERIOD)

        logger.debug('Entering auto triggered dissection process')

        def on_exit_clean_up():
            # cleaning up
            channel.queue_delete(reply_queue_name)


        #request to sniffing component
        body = OrderedDict()
        body['_type'] = request_message_type
        body['get_last'] = True
        corr_id = str(uuid.uuid4())

        channel.basic_qos(prefetch_count=1)
        channel.basic_publish(exchange=AMQP_EXCHANGE,
                              routing_key=request_r_key,

                              properties=pika.BasicProperties(
                                      reply_to=response_r_key,
                                      correlation_id=corr_id,
                                      content_type='application/json',
                              ),
                              body=json.dumps(body),
                              )

        time.sleep(1)
        # get message and drop all those with different corr_id
        method, header, body = channel.basic_get(queue=reply_queue_name)
        if body is not None:
            channel.basic_ack(delivery_tag=method.delivery_tag)

        while body is None or corr_id != header.correlation_id:
            method, header, body = channel.basic_get(queue=reply_queue_name)
            if body is not None:
                channel.basic_ack(delivery_tag=method.delivery_tag)

        if body is None:
            logger.error(channel,"Response timeout for request: routing_key: %s,body%s"%(request_message_type, json.dumps(body)))

        else:

            body = json.loads(body.decode('utf-8'), object_pairs_hook=OrderedDict)

            #check if response ok
            if body['ok'] is False:
                logger.error('Sniffing component coundlt process the %s request correcly, response: %s'
                              % (request_message_type, body))

            # elif corr_id != header.correlation_id:
            #     logger.debug('drop message, not intereted in this event. expected corr_id %s, but got %s'%(corr_id,header.correlation_id))

            else:
                # let's try to save the file and then push it to results repo
                pcap_file_base64 = ''
                pcap_file_base64 = body['value']
                filename = body['filename']
                # save pcap as file
                nb = _save_capture(filename, pcap_file_base64)


                if last_polled_pcap and last_polled_pcap==pcap_file_base64:
                    logger.debug('No new sniffed packets')
                else:
                    last_polled_pcap = pcap_file_base64

                    logger.info("Starting dissection of PCAP ...")

                    # response params
                    event_type = 'dissection.autotriggered'
                    event_r_key =  'control.dissection.info'

                    logger.info("Decoding PCAP file using base64 ...")

                    # if pcap file has less than 24 bytes then its an empty pcap file
                    if (nb <= 24):
                        logger.error("Empty PCAP received")

                    else:
                        logger.info("Pcap correctly saved %d B at %s" % (nb, TMPDIR))

                        # Lets dissect
                        try:
                            dissection = Dissector(TMPDIR + '/' + filename).dissect()

                            logger.debug('Dissected PCAP: %s' % json.dumps(dissection))

                            # prepare response with dissection info:
                            event = OrderedDict()
                            event.update({'_type': event_type})
                            event.update({'ok': True})
                            event.update({'token': _get_token()})
                            event.update({'frames': dissection})

                            channel.basic_publish(
                                    body=json.dumps(event, ensure_ascii=False),
                                    routing_key=event_r_key,
                                    exchange=AMQP_EXCHANGE,
                                    properties=pika.BasicProperties(
                                            content_type='application/json',
                                    )
                            )

                        except (TypeError, pure_pcapy.PcapError) as e:
                            logger.error("Error found trying to dissect %s"%str(e))

                        except Exception as e:
                            logger.error("Error found trying to dissect %s" % str(e))


def _amqp_reply(channel, props, response):
    # check first that sender didnt forget about reply to and corr id
    try:
        reply_to = props.reply_to
        correlation_id = props.correlation_id
        logger.info("reply_to: %s type: %s"%(str(reply_to),str(type(reply_to))))
        logger.info("corr_id: %s type: %s" % (str(correlation_id), str(type(correlation_id))))
    except KeyError:
        logger.error(msg='There is an error on the request, either reply_to or correlation_id not provided')
        return

    logger.debug('Sending reply through the bus: r_key: %s , corr_id: %s'%(reply_to,correlation_id))
    channel.basic_publish(
        body=json.dumps(response, ensure_ascii=False),
        routing_key=reply_to,
        exchange=AMQP_EXCHANGE,
        properties=pika.BasicProperties(
            content_type='application/json',
            correlation_id=correlation_id,
        )
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

        if protocol and protocol.lower()==prot_class.__name__.lower():
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
            print('skipped: %s'%prot_class.__name__)
            pass

    if answer is None or len(answer)==0:
        return None
    else:
        return answer

def _save_capture(filename,pcap_file_base64):
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
    #print(str(_get_protocol('CoAP')))
    #print(str(_get_protocol()))
    print(str(eval('CoAP')))
    dissection = Dissector(TMPDIR + '/TD_COAP_CORE_02.pcap').dissect()#eval('CoAP'))
    #dissection = Dissector(TMPDIR + '/tun_sniffed_coap.pcap').dissect(eval('CoAP'))
    print(dissection)
