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
from ttproto.core.typecheck import *
from collections import OrderedDict
import base64
import pika
import json, errno, logging, os

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

def bootsrap_amqp_interface():


    credentials = pika.PlainCredentials(AMQP_USER, AMQP_PASS)
    connection = pika.BlockingConnection(pika.ConnectionParameters(
                host=AMQP_SERVER,
                virtual_host=AMQP_VHOST,
                credentials=credentials))
    channel = connection.channel()

    services_queue_name = 'services_queue@%s' % COMPONENT_ID
    channel.queue_declare(queue=services_queue_name)

    channel.queue_bind(exchange=AMQP_EXCHANGE,
                       queue=services_queue_name,
                       routing_key='control.analysis.service')
    # Hello world message
    channel.basic_publish(
            body=json.dumps({'value': 'TAT is up!', '_type': 'analysis.info'}),
            routing_key='control.analysis.info',
            exchange=AMQP_EXCHANGE,
    )

    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(on_request, queue=services_queue_name)

    print(" [x] Awaiting for analysis requests")
    channel.start_consuming()



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
        logging.info("Decoding PCAP file into base64 ...")
        try:
            pcap_file_base64 = req_body_dict['value']
            filename = req_body_dict['filename']
            testcase_id = req_body_dict['testcase_id']
            testcase_ref = req_body_dict['testcase_ref']
            # save to file
            with open(os.path.join(TMPDIR, filename), "wb") as pcap_file:
                nb = pcap_file.write(base64.b64decode(pcap_file_base64))
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
            verdict['token'] = 'NOT YET IMPLEMENTED'
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

    else:
        api_error(ch,'Coulnt process the service request: %s' %str(req_body_dict))





