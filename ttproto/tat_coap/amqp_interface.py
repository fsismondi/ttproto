#!/usr/bin/env python3
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
from kombu.mixins import ConsumerMixin
from kombu import Connection, Exchange, Queue, Producer

import json, os, errno, logging, time


#AMQP: component identification & bus params
COMPONENT_ID = 'tat'
COMPONENT_DIR = 'ttproto/core/tat_coap'
DEFAULT_PLATFORM = "127.0.0.1:15672"
DEFAULT_EXCHANGE = "default"

# Directories
DATADIR = "data"
TMPDIR = "tmp"
LOGDIR = "log"

# Prefix and suffix for the hashes
HASH_PREFIX = 'tt'
HASH_SUFFIX = 'proto'
TOKEN_LENGTH = 28

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)


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


class ServiceHandler(ConsumerMixin):

    def __init__(self, amqp_connection):

        # queues & default exchange declaration
        self.connection = amqp_connection
        self.exchange = Exchange(DEFAULT_EXCHANGE, type="topic", durable=True)
        self.control_queue = Queue("control.analysis.service@{name}".format(name=COMPONENT_ID),
                                   exchange=self.exchange,
                                   routing_key='control.analysis.service',
                                   durable=False)

        self.producer = self.connection.Producer(serializer='json')


    def log_message(self, format, *args, append=""):
        global log_file
        host = self.address_string()

        txt = ("%s - - [%s] %s - %s\n%s" %
               (host,
                time.time(),
                format % args,
                self.headers.get("user-agent"),
                "".join("\t%s\n" % l for l in append.splitlines()),
                ))

        logging.debug()



    def api_error(self, message):
        """
            Function for generating a json error
            The error message is logged at the same time
        """
        self.log_message("%s error: %s", self.path, message)
        to_dump = OrderedDict()
        to_dump['_type'] = 'response'
        to_dump['ok'] = False
        to_dump['error'] = message
        print(json.dumps(to_dump))

    def do_GET(self):

        # Get the url and parse it
        url = urlparse(self.path)

        # ##### Personnal remarks
        #
        # For the moment, using this webserver is right but for scaling maybe a
        # strong web platform using a framework will be better. This one is
        # sufficient for the moment.
        #
        # We check on the path for whole uri, maybe we should bind a version to
        # a beginning like "/api/v1" and then bind the methods put behind it.
        #
        # ##### End of remarks

        # GET handler for the analyzer_getTestCases uri
        # It will give to the gui the list of the test cases
        #
        if url.path == '/api/v1/analyzer_getTestCases':

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the list of test cases
            try:
                test_cases = get_test_cases()
            except FileNotFoundError as fnfe:
                self.api_error(
                    'Problem during fetching the test cases list:\n' + str(fnfe)
                )
                return

            clean_test_cases = []
            for tc in test_cases:
                clean_test_cases.append(test_cases[tc]['tc_basic'])

            # If no test case found
            if len(clean_test_cases) == 0:
                self.api_error('No test cases found')
                return

            # The result to return
            json_result = OrderedDict()
            json_result['_type'] = 'response'
            json_result['ok'] = True
            json_result['content'] = clean_test_cases

            # Just give the json representation of the test cases list
            print(json.dumps(json_result))
            return

        # GET handler for the analyzer_getTestcaseImplementation uri
        # It will allow developpers to get the implementation script of a TC
        #
        # /param testcase_id => The unique id of the test case
        #

job_id = 0

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


def reopen_log_file(signum, frame):
    global log_file
    log_file = open(os.path.join(LOGDIR, "coap-webserver.log"), "a")
