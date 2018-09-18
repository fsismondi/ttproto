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

import http.server
import io
import sys
import os
import errno
import tempfile
import re
import time
import signal
import select
import subprocess
import cgi
import json
import hashlib
import base64
import requests
import email.feedparser
import email.message
from . import analysis
from collections import OrderedDict
from urllib.parse import urlparse, parse_qs
from ttproto.utils import pure_pcapy
from ttproto.core.lib.inet import coap
from ttproto.core.xmlgen import XHTML10Generator, XMLGeneratorControl

# Directories
from ttproto import DATADIR
from ttproto import TMPDIR
from ttproto import LOGDIR

# List to generate the changelog page
CHANGELOG = []
CHANGELOG_FIRST_COMMIT = "iot2-beta"


# ########################## ttproto API ########################### #

# Prefix and suffix for the hashes
HASH_PREFIX = 'tt'
HASH_SUFFIX = 'proto'
TOKEN_LENGTH = 28

# Magic header to identify a pcap file
PCAP_MAGIC_HEADER = b'\xd4\xc3\xb2\xa1'

# The different implemented protocols
PROTOCOLS = OrderedDict()

PROTOCOLS['None'] = OrderedDict()
PROTOCOLS['None']['class'] = None
PROTOCOLS['None']['description'] = 'No particular protocol'

PROTOCOLS['CoAP'] = OrderedDict()
PROTOCOLS['CoAP']['class'] = coap.CoAP
PROTOCOLS['CoAP']['description'] = 'CoAP protocol'

# The cache for the test cases
TEST_CASES = OrderedDict()

# ######################## End of API part ######################### #


def prepare_changelog():
    global CHANGELOG
    CHANGELOG = []

    try:
        lines = None

        # NOTE: limite log to first parent to avoid the burden of having
        #       verbose changelog about tool updates
        #    -> put tool updates in branch 'tool'
        #    -> put test suites updates in branch 'master'
        #    -> merge 'tool' into 'master' using « --no-ff --no-commit »
        #       and put summary changes about the tool
        git_cmd = [
            'git',
            'log',
            '--format=format:%cD\n%h\n%d\n%B\n_____end_commit_____',
            '--first-parent'
        ]

        if CHANGELOG_FIRST_COMMIT:
            git_cmd.append("%s^1.." % CHANGELOG_FIRST_COMMIT)

        git_log = iter(str(subprocess.Popen(
                git_cmd,
                stdout=subprocess.PIPE,
                close_fds=True,
            ).stdout.read(), "utf8", "replace").splitlines())

        while True:
            date = next(git_log)
            ver = next(git_log)
            tags = next(git_log)
            if tags:
                tags = tags[2:-1]
            lines = []
            while True:
                l = next(git_log)
                if l == "_____end_commit_____":
                    break
                lines.append(l)

            if lines and lines[-1] != "":
                lines.append("")  # ensure that there will be a \n at the end
            CHANGELOG.append((ver, tags, date, "\n".join(lines)))
    except StopIteration:
        pass
    except Exception as e:
        CHANGELOG = [(
            ("error when generating changelog(%s: %s)" % (type(e).__name__, e)),
            "",
            "",
            ""
        )]


def html_changelog(g):

    ctl = XMLGeneratorControl(g)

    g.h2("Changelog")
    for ver, tags, date, body in CHANGELOG:
        if tags:
            g.b("%s" % (tags))
            ctl.raw_write("<br>")  # FIXME: bug in xmlgen
        g.span("%s - %s\n\n" % (ver, date), style="color:#808080")

        g.pre("\t%s\n\n" % "\n\t".join(body.splitlines()))


# ########################## ttproto API ########################### #

# Function to get the test cases from files if not initialized
# Or directly from the global storage variable
# Can retrieve a single test case if wanted
# But doesn't use the analysis function, cf the remark
#
# /param testcase_id The id of the single test case if one wanted
#
# /remark If we ask for only one test case directly from the analysis function
# It does return an ImportError when it found the TC, it seems that it's trying
# to import a module with its name  cf analysis:220
def get_test_cases(testcase_id=None):

    # Get the global variable to store the test cases
    global TEST_CASES

    # If empty for the moment
    if len(TEST_CASES) == 0:

        # Own function to clean the datas received
        raw_test_cases = analysis.get_implemented_testcases()

        # Build the clean results list
        for raw_tc in raw_test_cases:

            tc_basic = OrderedDict()
            tc_basic['_type'] = 'tc_basic'
            tc_basic['id'] = raw_tc[0]
            tc_basic['objective'] = raw_tc[1]

            tc_implementation = OrderedDict()
            tc_implementation['_type'] = 'tc_implementation'
            tc_implementation['implementation'] = raw_tc[2]

            # Tuple, basic + implementation
            TEST_CASES[raw_tc[0]] = {
                'tc_basic': tc_basic,
                'tc_implementation': tc_implementation
            }

    # If only one asked
    if testcase_id is not None:
        if testcase_id in TEST_CASES:
            return TEST_CASES[testcase_id]
        else:
            return None

    # If everyone asked
    else:
        return TEST_CASES


# Function to check if a get parameter is correct
#
# /param par The get parameter to check (care it's a list)
# /param is_number If we expect it to be a number
#
# /return boolean telling if the get parameter is correct or not
#
def correct_get_param(par, is_number=False):
    return all((
        len(par) == 1,
        type(par[0]) == str,
        par[0] != '',
        not (
            is_number and (
                not par[0].isdigit() or int(par[0]) <= 0
            )
        )
    ))


# Function to check if a pcap file get parameter is a valid one
#
# /param bytes_data The pcap file, normally as bytes, but can be wrong
#
# /return boolean telling if the data entered is a pcap file
#
def valid_pcap_file(bytes_data):
    return all((
        bytes_data,
        type(bytes_data) == bytes,
        len(bytes_data) > 52,  # file header + (src, dest) adresses
        bytes_data[:4] == PCAP_MAGIC_HEADER
    ))


# Function to get a token, if there's a valid one entered just return it
# otherwise generate a new one
#
# /param tok The token if there's already one
#
# /return str A token, the same if there's already one, a new one otherwise
#
def get_token(tok=None):

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

    # Generate a token because there is none
    token = hashlib.sha1(
        str.encode((
            "%s%s%04d%s" %
            (
                HASH_PREFIX,
                time.time(),
                job_id,
                HASH_SUFFIX
            )
        ), encoding='utf-8')
    )
    token = base64.urlsafe_b64encode(token.digest()).decode()

    # Remove the '=' at the end of it, it is used by base64 for padding
    return token.replace('=', '')


# ######################## End of API part ######################### #


class UTF8Wrapper(io.TextIOBase):
    def __init__(self, raw_stream):
        self.__raw = raw_stream

    def write(self, string):

        return self.__raw.write(bytes(string, "utf-8"))


class BytesFeedParser(email.feedparser.FeedParser):
    """Like FeedParser, but feed accepts bytes."""

    def feed(self, data):
        super().feed(data.decode('ascii', 'surrogateescape'))


class RequestHandler(http.server.BaseHTTPRequestHandler):

    # ########################## ttproto API ########################### #
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

    # ######################## End of API part ######################### #

    def log_message(self, format, *args, append=""):
        global log_file
        host = self.address_string()
        if host in("172.17.42.1", "localhost", "127.0.0.1", "::1"):
            xff = self.headers.get("x-forwarded-for")
            if xff:
                host = xff

        txt = ("%s - - [%s] %s - %s\n%s" %
               (host,
                self.log_date_time_string(),
                format % args,
                self.headers.get("user-agent"),
                "".join("\t%s\n" % l for l in append.splitlines()),
                ))

        sys.stderr.write(txt)
        log_file.write(txt)
        log_file.flush()

    def do_GET(self):

        # Get the url and parse it
        url = urlparse(self.path)

        if url.path == "/coap-tool.sh":
            fp = open("coap-tool.sh", "rb")

            if not fp:
                self.send_response(500)
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/x-sh")
            self.end_headers()

            self.wfile.write(fp.read())
            return
        elif url.path == "/doc/ETSI-CoAP4-test-list.pdf":
            fp = open("doc/ETSI-CoAP4-test-list.pdf", "rb")

            if not fp:
                self.send_response(500)
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.end_headers()

            self.wfile.write(fp.read())
            return
        elif url.path == "/doc/Additive-IRISA-CoAP-test-list.pdf":
            fp = open("doc/Additive-IRISA-CoAP-test-list.pdf", "rb")

            if not fp:
                self.send_response(500)
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.end_headers()

            self.wfile.write(fp.read())
            return
        elif url.path == "/doc/Additive-IRISA-CoAP-test-description.pdf":
            fp = open("doc/Additive-IRISA-CoAP-test-description.pdf", "rb")

            if not fp:
                self.send_response(500)
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.end_headers()

            self.wfile.write(fp.read())
            return

        # ########################## ttproto API ########################### #

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
        elif url.path == '/api/v1/analyzer_getTestCases':

            # Send the header
            self.send_response(200)
            self.send_header("Content-Type", "application/json;charset=utf-8")
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the list of test cases
            test_cases = get_test_cases()
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
        elif url.path == '/api/v1/analyzer_getTestcaseImplementation':

            # Send the header
            self.send_response(200)
            self.send_header("Content-Type", "application/json;charset=utf-8")
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the parameters
            params = parse_qs(url.query)

            try:

                # Check parameters
                if any((
                    len(params) != 1,
                    'testcase_id' not in params,
                    not correct_get_param(params['testcase_id'])
                )):
                    raise

            # Catch errors (key mostly) or if wrong parameter
            except:
                self.api_error(
                    "Incorrects GET parameters, expected '?testcase_id={string}'"
                )
                return

            # Get the test case
            test_case = get_test_cases(params['testcase_id'][0])
            if test_case is None or len(test_case) == 0:
                self.api_error('Test case %s not found' % params['testcase_id'][0])
                return

            # The result to return
            json_result = OrderedDict()
            json_result['_type'] = 'response'
            json_result['ok'] = True
            json_result['content'] = [
                test_case['tc_basic'],
                test_case['tc_implementation']
            ]

            # Here the process from ttproto core
            print(json.dumps(json_result))
            return

        # GET handler for the analyzer_getProtocols uri
        # It will give to the gui the list of the protocols implemented
        #
        elif url.path in (
            '/api/v1/analyzer_getProtocols',
            '/api/v1/dissector_getProtocols'
        ):

            # Send the header
            self.send_response(200)
            self.send_header("Content-Type", "application/json;charset=utf-8")
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # The result to return
            json_result = OrderedDict()
            json_result['_type'] = 'response'
            json_result['ok'] = True
            json_result['content'] = []

            # Get protocols from the list
            for prot_name in PROTOCOLS:
                prot = OrderedDict()
                prot['_type'] = 'implemented_protocol'
                prot['name'] = prot_name
                prot['description'] = PROTOCOLS[prot_name]['description']
                json_result['content'].append(prot)

            # Maybe it will be good to get those from a file/db in the future

            # Just give the json representation of the test cases list
            print(json.dumps(json_result))
            return

        # GET handler for the analyzer_getFrames and dissector_getFrames uri
        # It will allow an user to get a single frame from the previous pcap
        # if no frame_id provided, otherwise it will return all the frames
        #
        # /param token => The token of the corresponding pcap file
        # /param protocol_selection => The protocol we want to filter on
        # /param frame_id (optional) => The id of the wanted frame
        #
        # /remark We redirect to the same function but later those two
        # may diverge
        #
        elif url.path in (
            '/api/v1/analyzer_getFrames',
            '/api/v1/dissector_getFrames'
        ):

            # Send the header
            self.send_response(200)
            self.send_header("Content-Type", "application/json;charset=utf-8")
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the parameters
            params = parse_qs(url.query)
            try:

                # Only token and protocol_selection
                if len(params) == 2:
                    if any((
                        'token' not in params,
                        'protocol_selection' not in params,
                        not correct_get_param(params['token']),
                        not correct_get_param(params['protocol_selection'])
                    )):
                        raise

                # token, protocol_selection and frame_id
                elif len(params) == 3:
                    if any((
                        'token' not in params,
                        'protocol_selection' not in params,
                        'frame_id' not in params,
                        not correct_get_param(params['token']),
                        not correct_get_param(params['frame_id'], is_number=True),
                        not correct_get_param(params['protocol_selection'])
                    )):
                        raise

                # Wrong number of parameters
                else:
                    raise

            # Catch errors (key mostly) or if wrong parameter
            except:
                self.api_error(
                    "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
                )
                return

            # Format the id before passing it to the process function
            token = params['token'][0]
            protocol_selection = params['protocol_selection'][0]

            # Check the protocol
            if protocol_selection not in PROTOCOLS.keys():
                self.api_error(
                    'Unknown %s protocol' % protocol_selection
                )
                return

            # Create the frames object
            frames = []

            # Get the json file
            try:
                json_path = os.path.join(
                    TMPDIR,
                    "%s.json" % token
                )
                with open(json_path, 'r') as json_fp:
                    frames = json.load(json_fp, object_pairs_hook=OrderedDict)
            except:
                self.api_error(
                    'Session identified by token %s not found' % token
                )
                return

            # If a single file asked
            if len(params) == 3:
                frame_id = int(params['frame_id'][0])
                for frame in frames:
                    if frame['id'] == frame_id:
                        frames = [frame]

                # If no frame with this id
                if len(frames) != 1:
                    self.api_error(
                        'No frame with id=%u found' % frame_id
                    )
                    return

            # The result to return
            json_result = OrderedDict()
            json_result['_type'] = 'response'
            json_result['ok'] = True

            token_res = OrderedDict()
            token_res['_type'] = 'token'
            token_res['value'] = token

            frames.insert(0, token_res)

            json_result['content'] = frames

            # Dump the json result
            print(json.dumps(json_result))
            return

        # GET handler for the dissector_getFramesSummary uri
        # It will allow an user to get all the frames summary
        #
        # /param token => The token of the corresponding pcap file
        # /param protocol_selection => The protocol we want to filter on
        #
        elif url.path == '/api/v1/dissector_getFramesSummary':

            # Send the header
            self.send_response(200)
            self.send_header("Content-Type", "application/json;charset=utf-8")
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the parameters
            params = parse_qs(url.query)
            try:

                # Only token and protocol_selection
                if any((
                    len(params) != 2,
                    'token' not in params,
                    'protocol_selection' not in params,
                    not correct_get_param(params['token']),
                    not correct_get_param(params['protocol_selection'])
                )):
                    raise

            # Catch errors (key mostly) or if wrong parameter
            except:
                self.api_error(
                    "Incorrects parameters expected '?token={string}&protocol_selection={string}'"
                )
                return

            # Format the id before passing it to the process function
            token = params['token'][0]
            protocol_selection = params['protocol_selection'][0]

            # Check the protocol
            if protocol_selection not in PROTOCOLS.keys():
                self.api_error(
                    'Unknown %s protocol' % protocol_selection
                )
                return

            # Get the dump file
            try:
                pcap_path = os.path.join(
                    TMPDIR,
                    "%s.dump" % token
                )
                frames_summary = analysis.basic_dissect_pcap_to_list(
                    pcap_path,
                    PROTOCOLS[protocol_selection]['class']
                )
            except:
                self.api_error(
                    'Session identified by token %s not found' % token
                )
                return

            # The result to return
            json_result = OrderedDict()
            json_result['_type'] = 'response'
            json_result['ok'] = True

            token_res = OrderedDict()
            token_res['_type'] = 'token'
            token_res['value'] = token
            json_result['content'] = []
            json_result['content'].append(token_res)

            # Add each frame summary
            for f_id, f_sum in frames_summary:
                summary = OrderedDict()
                summary['_type'] = 'frame_summary'
                summary['frame_id'] = f_id
                summary['frame_summary'] = f_sum
                json_result['content'].append(summary)

            # Dump the json result
            print(json.dumps(json_result))
            return

        # ######################## End of API part ######################### #

        elif url.path != "/":
            self.send_error(404)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html;charset=utf-8")
        self.end_headers()

        with XHTML10Generator(output=UTF8Wrapper(self.wfile)) as g:

            with g.head:
                g.title("IRISA CoAP interoperability Testing Tool")
                g.style("img {border-style: solid; border-width: 20px; border-color: white;}", type="text/css")

            g.h1("IRISA CoAP interoperability Testing Tool")

            g.b("Tool version: ")
            g("%s" % analysis.TOOL_VERSION)
            with g.br():  # FIXME: bug generator
                pass
            with g.form(method="POST", action="submit", enctype="multipart/form-data"):
                g("This tool(more details at ")
                g.a("www.irisa.fr/tipi", href="http://www.irisa.fr/tipi/wiki/doku.php/passive_validation_tool_for_coap")
                g(") allows executing CoAP interoperability test suites(see below Available Test Scenarios) on the provided traces of CoAP Client-Server interactions.")
                g.br()
                g.h3("Available Test Scenarios:")
                g("- ETSI COAP#4 Plugtest scenarios: ")
                g.a("ETSI-CoAP4-test-list", href="doc/ETSI-CoAP4-test-list.pdf")
                g(", ")
                g.a("ETSI-CoAP4-test-description", href="https://github.com/cabo/td-coap4/")
                with g.br():  # FIXME: bug in generation if we remove the with context
                    pass
                g("- Additive test scenarios developed by IRISA/Tipi Group: ")
                g.a("Additive-IRISA-CoAP-test-list", href="doc/Additive-IRISA-CoAP-test-list.pdf")
                g(", ")
                g.a("Additive-IRISA-CoAP-test-description", href="doc/Additive-IRISA-CoAP-test-description.pdf")
                with g.br():  # FIXME: bug in generation if we remove the with context
                    pass
                g.h3("IETF RFCs/Drafts covered:")
                g("- CoAP CORE(")
                g.a("RFC7252", href="http://tools.ietf.org/html/rfc7252")
                g(")")
                with g.br():  # FIXME: bug in generation if we remove the with context
                    pass
                g("- CoAP OBSERVE(")
                g.a("draft-ietf-core-observe-16", href="http://tools.ietf.org/html/draft-ietf-core-observe-16")
                g(")")
                with g.br():  # FIXME: bug in generation if we remove the with context
                    pass
                g("- CoAP BLOCK(")
                g.a("draft-ietf-core-block-17", href="http://tools.ietf.org/html/draft-ietf-core-block-17")
                g(")")
                g.br()
                with g.br():  # FIXME: bug in generation if we remove the with context
                    pass

                g("==========================================================================================")
                with g.br():  # FIXME: bug in generation if we remove the with context
                    pass
                g("Submit your traces(pcap format). \nWarning!! pcapng format is not supported; you should convert your pcapng file to pcap format.")
                with g.br():  # FIXME: bug in generation if we remove the with context
                    pass
                g.input(name="file", type="file", size=60)
                with g.br():  # FIXME: bug in generation if we remove the with context
                    pass
                g("Configuration")
                g.br()
                with g.select(name="profile"):
                    g.option("Client <-> Server", value="client", selected="1")
                    g.option("Reverse-Proxy <-> Server", value="reverse-proxy")
                with g.br():  # FIXME: bug in generation if we remove the with context
                    pass
                g("Optional regular expression for selecting scenarios(eg: ")
                g.tt("CORE_0[1-2]")
                g(" will run only ")
                g.tt("TD_COAP_CORE_01")
                g(" and ")
                g.tt("TD_COAP_CORE_02")
                g(")")
                g.br()
                g.input(name="regex", size=60)
                g.br()
                with g.br():  # FIXME: bug in generation if we remove the with context
                    pass
                with g.input(name="agree", type="checkbox", value="1"):
                    pass
                g("I agree to leave a copy of this file on the server(for debugging purpose). Thanks")

                g.br()

                with g.input(name="urifilter", type="checkbox", value="1"):
                    pass
                g("Filter conversations by URI(/test vs. /separate vs. /.well-known/core  ...) to reduce verbosity")

                g.br()
                g.br()
                g.input(type="submit")
                with g.br():  # FIXME: bug generator
                    pass
                g.b("Note:")
                g(" alternatively you can use the shell script ")
                g.a("coap-tool.sh", href="coap-tool.sh")
                g(" to capture and submit your traces to the server(requires tcpdump and curl installed on your system).")

            g.a(href="http://www.irisa.fr/tipi").img(src="http://www.irisa.fr/tipi/wiki/lib/tpl/tipi_style/images/irisa.jpg", height="40")

            g.a(href="http://www.irisa.fr/tipi").img(src="http://www.irisa.fr/tipi/wiki/lib/tpl/tipi_style/images/tipi_small.png", height="50")

            html_changelog(g)

    def do_POST(self):

        # The job counter
        global job_id
        job_id += 1

        # ########################## ttproto API ########################### #

        # POST handler for the analyzer_testCaseAnalyze uri
        # It will allow users to analyze a pcap file corresponding to a TC
        #
        # \param pcap_file => The pcap file that we want to analyze
        # \param token => The token previously provided
        # \param testcase_id => The id of the corresponding test case
        # The pcap_file or the token is required, having both is also forbidden
        #
        if self.path == '/api/v1/analyzer_testCaseAnalyze':

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the content type
            try:
                content_type = cgi.parse_header(self.headers['Content-Type'])
            except TypeError:
                self.api_error(
                    "Non empty POST datas and format of 'multipart/form-data' expected"
                )
                return

            # Get post values
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                keep_blank_values=True,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': content_type[0]
                })

            # Check that we have the two values
            if any((
                len(form) != 2,
                'testcase_id' not in form,
                all((  # None of the two required => Error
                    'pcap_file' not in form,
                    'token' not in form
                )),
                all((  # Both of them => Error
                    'pcap_file' in form,
                    'token' in form
                ))
            )):
                self.api_error(
                    'Expected POST=([pcap_file={file}|token={text}], testcase_id={text})'
                )
                return

            # Get the test case and its informations
            testcase_id = form.getvalue('testcase_id')
            if not type(testcase_id) == str:
                self.api_error('The value of the testcase_id should be a string from text input')
                return

            # Try to get the test case
            test_case = get_test_cases(testcase_id)

            # If no TC found
            if test_case is None:
                self.api_error('Test case %s not found' % testcase_id)
                return

            # Get the token
            token = form.getvalue('token')

            # Get analysis results from the token
            if token:

                # Just get the path
                pcap_path = os.path.join(
                    TMPDIR,
                    token + '.dump'
                )

            # Get analysis results from the pcap file
            else:

                # Check headers
                if any((
                    len(content_type) == 0,
                    content_type[0] is None,
                    content_type[0] != 'multipart/form-data'
                )):
                    self.api_error(
                        "POST format of 'multipart/form-data' expected, no file input 'pcap_file' found"
                    )
                    return

                # Get the same token or generate a new one
                token = get_token(token)

                # Get and check the pcap file entered
                pcap_file = form.getvalue('pcap_file')
                if not valid_pcap_file(pcap_file):
                    self.api_error("Expected 'pcap_file' to be a non empty file")
                    return

                # Path to save the file
                pcap_path = os.path.join(
                    TMPDIR,
                    token + '.dump'
                )

                # Write the pcap file to a temporary destination
                try:
                    with open(pcap_path, 'wb') as f:
                        f.write(pcap_file)
                except:
                    self.api_error(
                        "Couldn't write the temporary file %s"
                        %
                        pcap_path
                    )
                    return

                # Get the dissection from analysis tool
                try:
                    dissection = analysis.dissect_pcap_to_list(pcap_path)
                except:
                    self.api_error(
                        "Couldn't read the temporary file %s"
                        %
                        pcap_path
                    )
                    return

                # Save the json dissection result into a file
                json_save = os.path.join(
                    TMPDIR,
                    token + '.json'
                )
                try:
                    with open(json_save, 'w') as f:
                        json.dump(dissection, f)
                except:
                    self.api_error("Couldn't write the json file")
                    return

            # Get the result of the analysis
            analysis_results = analysis.analyse_file_rest_api(
                                pcap_path,
                                False,
                                None,
                                testcase_id,
                                'client',
                                True
                            )

            # self.log_message("###############################################")
            # self.log_message("Verdict description is : %s", analysis_results[0][3])
            # self.log_message("###############################################")

            # Error for some test cases that the analysis doesn't manage to get
            try:
                assert type(analysis_results) == list
                assert len(analysis_results) == 1  # >= if we can receive more
                assert type(analysis_results[0]) == tuple
                assert len(analysis_results[0]) == 4
                assert type(analysis_results[0][0]) == str
                assert type(analysis_results[0][1]) == str
                assert type(analysis_results[0][2]) == list
                assert type(analysis_results[0][3]) == str
                assert analysis_results[0][0] == test_case['tc_basic']['id']
            except AssertionError:
                self.api_error(
                    'Problem with the analyse of TC %s, wrong result received'
                    %
                    testcase_id
                )
                return

            # Only take the first
            verdict = OrderedDict()
            verdict['_type'] = 'verdict'
            verdict['verdict'] = analysis_results[0][1]
            verdict['description'] = analysis_results[0][3]
            verdict['review_frames'] = analysis_results[0][2]

            token_res = OrderedDict()
            token_res['_type'] = 'token'
            token_res['value'] = token

            # Prepare the result to return
            json_result = OrderedDict()
            json_result['_type'] = 'response'
            json_result['ok'] = True
            json_result['content'] = [
                token_res,
                test_case['tc_basic'],
                verdict
            ]

            # Here we will analyze the pcap file and get the results as json
            print(json.dumps(json_result))
            return

        # POST handler for the analyzer_allMightyAnalyze uri
        # It will allow users to analyze a pcap file without giving
        # a corresponding test case
        #
        # \param pcap_file => The pcap file that we want to analyze
        # \param token => The token previously provided
        # The pcap_file or the token is required, having both is also forbidden
        #
        elif self.path == '/api/v1/analyzer_allMightyAnalyze':

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Not implemented for the moment
            self.api_error(
                "This method is not implemented yet, please come back later"
            )
            return

        # POST handler for the dissector_dissectFile uri
        # It will allow users to analyze a pcap file corresponding to a TC
        #
        # \param pcap_file => The pcap file that we want to dissect
        # \param protocol_selection => The protocol name
        #
        elif self.path == '/api/v1/dissector_dissectFile':

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the content type
            try:
                content_type = cgi.parse_header(self.headers['Content-Type'])
            except TypeError:
                self.api_error(
                    "Non empty POST datas and format of 'multipart/form-data' expected"
                )
                return

            # Check headers
            if any((
                len(content_type) == 0,
                content_type[0] is None,
                content_type[0] != 'multipart/form-data'
            )):
                self.api_error(
                    "POST format of 'multipart/form-data' expected, no file input 'pcap_file' found"
                )
                return

            # Get post values
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': content_type[0]
                })

            # Check the parameters passed
            if any((
                len(form) != 2,
                'pcap_file' not in form,
                'protocol_selection' not in form
            )):
                self.api_error(
                    'Expected POST=(pcap_file={file}, protocol_selection={text})'
                )
                return

            # Check the protocol_selection value
            protocol_selection = form.getvalue('protocol_selection')
            if not type(protocol_selection) == str:
                self.api_error('Expected protocol_selection post value to be a text (eq string)')
                return

            # In function of the protocol asked
            try:
                prot = PROTOCOLS[protocol_selection]
            except KeyError:
                self.api_error('Unknown protocol %s' % protocol_selection)
                return

            # Generate a new token
            token = get_token()

            # Get the pcap file
            pcap_file = form.getvalue('pcap_file')
            if valid_pcap_file(pcap_file):

                # Path to save the file
                pcap_path = os.path.join(
                    TMPDIR,
                    token + '.dump'
                )

                # Write the pcap file to a temporary destination
                try:
                    with open(pcap_path, 'wb') as f:
                        f.write(pcap_file)
                except:
                    self.api_error("Couldn't write the temporary file")
                    return
            else:
                self.api_error(
                    "Expected 'pcap_file' to be a non empty pcap file"
                )
                return

            # Prepare the result to return
            json_result = OrderedDict()
            json_result['_type'] = 'response'
            json_result['ok'] = True

            token_res = OrderedDict()
            token_res['_type'] = 'token'
            token_res['value'] = token

            # Get the dissection from analysis tool
            try:
                dissection = analysis.dissect_pcap_to_list(pcap_path)
            except:
                self.api_error("Couldn't read the temporary file")
                return

            # Save the json dissection result into a file
            json_save = os.path.join(
                TMPDIR,
                token + '.json'
            )
            try:
                with open(json_save, 'w') as f:
                    json.dump(dissection, f)
            except:
                self.api_error("Couldn't write the json file")
                return

            # Add the token to the results
            dissection.insert(0, token_res)

            # The json result to return
            json_result['content'] = dissection

            # Here we will analyze the pcap file and get the results as json
            print(json.dumps(json_result))
            return

        # ######################## End of API part ######################### #

        elif (self.path == "/submit"):

            if os.fork():
                # close the socket right now(because the
                # requesthandler may do a shutdown(), which triggers a
                # SIGCHLD in the child process)
                self.connection.close()
                return

            parser = BytesFeedParser()
            ct = self.headers.get("Content-Type")
            if not ct.startswith("multipart/form-data;"):
                self.send_error(400)
                return

            parser.feed(bytes("Content-Type: %s\r\n\r\n" % ct, "ascii"))
            parser.feed(self.rfile.read(int(self.headers['Content-Length'])))
            msg = parser.close()

            # agree checkbox is selected
            for part in msg.get_payload():
                if isinstance(part, email.message.Message):
                    disposition = part.get("content-disposition")
                    if disposition and 'name="agree"' in disposition:
                        agree = True
                        break
            else:
                agree = False

            # urifilter checkbox is selected
            for part in msg.get_payload():
                if isinstance(part, email.message.Message):
                    disposition = part.get("content-disposition")
                    if disposition and 'name="urifilter"' in disposition:
                        urifilter = True
                        break
            else:
                urifilter = False

            # content of the regex box
            for part in msg.get_payload():
                if isinstance(part, email.message.Message):
                    disposition = part.get("content-disposition")
                    if disposition and 'name="regex"' in disposition:
                        regex = part.get_payload()
                        if not regex:
                            regex = None
                        break
            else:
                regex = None

            # profile radio buttons
            for part in msg.get_payload():
                if isinstance(part, email.message.Message):
                    disposition = part.get("content-disposition")
                    if disposition and 'name="profile"' in disposition:
                        profile = part.get_payload()
                        break
            else:
                profile = "client"

            # receive the pcap file
            for part in msg.get_payload():
                if isinstance(part, email.message.Message):
                    disposition = part.get("content-disposition")
                    if disposition and 'name="file"' in disposition:
                        mo = re.search('filename="([^"]*)"', disposition)

                        orig_filename = mo.group(1) if mo else None

                        timestamp = time.strftime("%y%m%d_%H%M%S")

                        pcap_file = os.path.join(
                                (DATADIR if agree else TMPDIR),
                                "%s_%04d.dump" % (timestamp, job_id)
                        )
                        self.log_message("uploading %s(urifilter=%r, regex=%r)", pcap_file, urifilter, regex)
                        with open(pcap_file, "wb") as fd:
                            # FIXME: using hidden API(._payload) because it seems that there is something broken with the encoding when getting the payload using .get_payload()
                            fd.write(part._payload.encode("ascii", errors="surrogateescape"))

                        break
            else:
                self.send_error(400)
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html;charset=utf-8")
            self.end_headers()

            out = UTF8Wrapper(self.wfile)

            self.wfile.flush()

            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            try:
                exceptions = []
                analysis.analyse_file_html(pcap_file, orig_filename, urifilter, exceptions, regex, profile)
                for tc in exceptions:
                    self.log_message("exception in %s", type(tc).__name__, append=tc.exception)
            except pure_pcapy.PcapError:
                print("Bad file format!")

            shutdown()

        # If we didn't manage to bind the request
        else:
            self.send_error(404)
            return

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
    log_file = open(os.path.join(LOGDIR, "webserver.log"), "a")
