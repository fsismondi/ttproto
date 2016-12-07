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

from ttproto.core.analyzer import Analyzer
from ttproto.core.dissector import Dissector
from ttproto.core.typecheck import typecheck, optional, either
from collections import OrderedDict
import base64
import pika
import time, hashlib
import json, errno, logging, os
from ttproto.utils import pure_pcapy
# this imports all protocol implementations
from ttproto.core.lib.all import *

PCAP_DIR = 'finterop/sniffer/dumps'
ALLOWED_EXTENSIONS = set(['pcap'])



#AMQP: component identification & bus params
COMPONENT_ID = 'tat'
COMPONENT_DIR = 'ttproto/tat_coap'

# Directories
DATADIR = "data"
TMPDIR = "tmp"
LOGDIR = "log"

# Prefix and suffix for the hashes
HASH_PREFIX = 'tt'
HASH_SUFFIX = 'proto'
TOKEN_LENGTH = 28

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

# rewrite default values with ENV variables
try:
    AMQP_SERVER = str(os.environ['AMQP_SERVER'])
    AMQP_USER = str(os.environ['AMQP_USER'])
    AMQP_PASS = str(os.environ['AMQP_PASS'])
    AMQP_VHOST = str(os.environ['AMQP_VHOST'])
    AMQP_EXCHANGE = str(os.environ['AMQP_EXCHANGE'])

    logging.info('Env vars for AMQP connection succesfully imported')

except KeyError as e:
    logging.error(' Cannot retrieve environment variables for AMQP connection')

def bootstrap_amqp_interface():


    credentials = pika.PlainCredentials(AMQP_USER, AMQP_PASS)
    connection = pika.BlockingConnection(pika.ConnectionParameters(
                host=AMQP_SERVER,
                virtual_host=AMQP_VHOST,
                credentials=credentials))
    channel = connection.channel()

    services_queue_name = 'services_queue@%s' % COMPONENT_ID
    channel.queue_declare(queue=services_queue_name)

    # subscribe to analysis services requests
    channel.queue_bind(exchange=AMQP_EXCHANGE,
                       queue=services_queue_name,
                       routing_key='control.analysis.service')

    # subscribe to dissection servives requests
    channel.queue_bind(exchange=AMQP_EXCHANGE,
                       queue=services_queue_name,
                       routing_key='control.dissection.service')


    # Hello world message from tat
    channel.basic_publish(
            body=json.dumps({'value': 'TAT is up!', '_type': 'analysis.info'}),
            routing_key='control.analysis.info',
            exchange=AMQP_EXCHANGE,
    )

    # Hello world message from dissector (api implemented by this component too)
    channel.basic_publish(
            body=json.dumps({'value': 'Dissector is up!', '_type': 'dissection.info'}),
            routing_key='control.dissection.info',
            exchange=AMQP_EXCHANGE,
    )

    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(on_request, queue=services_queue_name)

    print(" [x] Awaiting for analysis requests")
    channel.start_consuming()







def on_request(ch, method, props, body):

    req_body_dict = json.loads(body.decode('ascii'))
    logging.info("Service request received: %s, body: %s" %(str(req_body_dict),str(body)))
    logging.info(type(body))

    try:
        # get type to trigger the right ttproto call
        req_type = req_body_dict['_type']

    except Exception as e:
        api_error(ch,str(e))

    if req_type == 'analysis.testcase.analyze':
        logging.info("Starting analysis of PCAP ...")
        ch.basic_ack(delivery_tag=method.delivery_tag)
        logging.info("Decoding PCAP file using base64 ...")
        try:
            pcap_file_base64 = req_body_dict['value']
            filename = req_body_dict['filename']
            testcase_id = req_body_dict['testcase_id']
            testcase_ref = req_body_dict['testcase_ref']

            nb = _save_capture(filename,pcap_file_base64)

            # if pcap file has less than 24 bytes then its an empty pcap file
            if (nb <= 24):
                ch.basic_publish(exchange=AMQP_EXCHANGE,
                                 routing_key=props.reply_to,
                                 properties=pika.BasicProperties(correlation_id= \
                                                                     props.correlation_id),
                                 body=json.dumps(
                                         {
                                             'message': 'Empty PCAP file received',
                                             'ok': False,
                                             '_type': req_type,

                                         }))
                logging.error("Empty PCAP received")
                return

            else:
                logging.info("Pcap correctly saved %d B at %s" % (nb, TMPDIR))

            # we run the analysis
            analysis_results = Analyzer('tat_coap').analyse(os.path.join(TMPDIR, filename), testcase_id)
            print(str(analysis_results))

        except Exception as e:
            api_error(ch,str(e))
            raise e


            #let's prepare the message
        try:
            verdict = OrderedDict()
            verdict['_type'] = 'analysis.testcase.analyze.verdict'
            verdict['ok'] = True
            verdict['verdict'] = analysis_results[1]
            # TODO make a description less verborragic -> fix in ttproto.analyse method , not here..
            verdict['description'] = analysis_results[3]
            verdict['review_frames'] = analysis_results[2]
            verdict['partial_verdicts'] = analysis_results[4]
            verdict['token'] = _get_token()
            verdict['testcase_id'] = testcase_id
            verdict['testcase_ref'] = testcase_ref
            logging.info("Analysis response sent: " + str(json.dumps(verdict)))

        except Exception as e :
            api_error(ch, str(e))
            raise e

        logging.info("Sending test case analysis through the AMQP interface ...")
        ch.basic_publish(exchange=AMQP_EXCHANGE,
                          routing_key=props.reply_to,
                          properties=pika.BasicProperties(correlation_id = \
                                                              props.correlation_id),
                          body=json.dumps(verdict))

    elif req_type == 'dissection.dissectcapture':
        ch.basic_ack(delivery_tag=method.delivery_tag)
        logging.info("Starting dissection of PCAP ...")

        pcap_file_base64 = req_body_dict['value']
        filename = req_body_dict['filename']

        proto_matched = None

        try:
            if 'protocol_selection' in req_body_dict.keys():
                proto_filter = req_body_dict['protocol_selection']

                # Check the protocol_selection value
                if not type(proto_filter) == str:
                    api_error(ch, 'Expected protocol_selection post value to be a text (eq string)')
                    return

                # In function of the protocol asked
                proto_matched = get_protocol(proto_filter)
                if proto_matched is None:
                    api_error(ch, 'Unknown protocol %s' % proto_filter)
                    return
        except Exception as e:
            logging.error(str(e))


        logging.info("Decoding PCAP file using base64 ...")

        # save pcap as file
        nb = _save_capture(filename, pcap_file_base64)

        # if pcap file has less than 24 bytes then its an empty pcap file
        if (nb <= 24):
            ch.basic_publish(exchange=AMQP_EXCHANGE,
                             routing_key=props.reply_to,
                             properties=pika.BasicProperties(correlation_id= \
                                                                 props.correlation_id),
                             body=json.dumps(
                                     {
                                         'message': 'Empty PCAP file received',
                                         'ok': False,
                                         '_type': req_type,

                                     }))
            logging.error("Empty PCAP received")
            return

        else:
            logging.info("Pcap correctly saved %d B at %s" % (nb, TMPDIR))


        # Get the dissection from dissector tool
        try:
            if len(proto_matched) == 1:
                dissection = Dissector(TMPDIR + '/' + filename).dissect(eval(proto_matched[0]['name']))
            else:
                dissection = Dissector(TMPDIR + '/' + filename).dissect()

            logging.debug('Dissected PCAP: %s' %json.dumps(dissection))

        except TypeError as e:
            api_error(ch, 'Dissector error: ' + str(e))
            return
        except pure_pcapy.PcapError:
            api_error(
                    ch,
                    "Expected 'pcap_file' to be a non empty pcap file"
            )
            return
        except:
            api_error(
                    ch,
                    "Couldn't read the file %s and protocol is %s"
                        %
                        (
                            filename,
                            str(proto_matched)
                        )
            )
            return

        # prepare response with dissection info:
        response = OrderedDict()
        response.update({'_type': req_type})
        response.update({'ok' : True})
        response.update({'token': _get_token()})
        response.update({'frames': dissection})

        logging.info("Sending test case analysis through the AMQP interface ...")

        ch.basic_publish(exchange=AMQP_EXCHANGE,
                          routing_key=props.reply_to,
                          properties=pika.BasicProperties(correlation_id = \
                                                              props.correlation_id),
                          body=json.dumps(response))




    else:
        api_error(ch,'Coulnt process the service request: %s' %str(req_body_dict))




## AUXILIARY FUNCTIONS ##
@typecheck
def get_test_cases(
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


def api_error( amqp_channel, error_msg):
    """
        Function for generating a json error
        The error message is logged at the same time
    """
    logging.error(' Critical exception found: %s' % error_msg)
    # lets push the error message into the bus
    amqp_channel.basic_publish(
        body=json.dumps(
            {
                '_type': 'analysis.error',
                'message': error_msg
            }
        ),
        exchange=AMQP_EXCHANGE,
        routing_key='control.analysis.error'
    )

@typecheck
def get_protocol(
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
    print(str(prot_classes))

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
    print(str(get_protocol('CoAP')))
    #print(str(get_protocol()))