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
import cgitb
import json
import hashlib
import base64
import requests
import email.feedparser
import email.message
from . import analysis
from urllib.parse import urlparse, parse_qs
from ttproto.utils import pure_pcapy
from ttproto.core.lib.inet import coap
from ttproto.core.xmlgen import XHTML10Generator, XMLGeneratorControl


DATADIR = "data"
TMPDIR = "tmp"
LOGDIR = "log"

CHANGELOG = []

HASH_PREFIX = 'tt'
HASH_SUFFIX = 'proto'
API_URL = 'http://127.0.0.1:2080'

CHANGELOG_FIRST_COMMIT = "iot2-beta"


# ########################## ttproto API ########################### #

def api_error(message):
    """
        Function for generating a json error
    """
    print(json.dumps({
        '_type': 'response',
        'ok': False,
        'error': message
    }))

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


# prepare_changelog()

def html_changelog(g):

    ctl = XMLGeneratorControl(g)

    g.h2("Changelog")
    for ver, tags, date, body in CHANGELOG:
        if tags:
            g.b("%s" % (tags))
            ctl.raw_write("<br>")  # FIXME: bug in xmlgen
        g.span("%s - %s\n\n" % (ver, date), style="color:#808080")

        g.pre("\t%s\n\n" % "\n\t".join(body.splitlines()))


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

        # GET handler for the get_testcase_implementation uri
        # It will allow developpers to get the implementation script of a TC
        #
        # /param testcase_id => The unique id of the test case
        #
        elif url.path == '/api/v1/testcase_getTestcaseImplementation':

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
                    len(params['testcase_id']) != 1
                )):
                    raise

            # Catch errors (key mostly) or if wrong parameter
            except:
                api_error(
                    'Incorrects parameters expected \'?testcase_id=[string]\''
                )
                return

            # Get the id
            testcase_id = params['testcase_id'][0]

            # FIXME: The method throw an ImportError when it found the TC
            # It seems that it's trying to import a module with its name
            # CF analysis:220

            # Try to get the test case
            try:
                test_cases = analysis.get_implemented_testcases(testcase_id)
            except FileNotFoundError:
                api_error(
                    'No test case with the id %s' % testcase_id
                )
                return

            # FIXME: Don't forget to remove this block when the bug is fixed
            except ImportError:
                os.chdir('../../..')
                api_error(
                    'TC %s found but a bug is to fix' % testcase_id
                )
                return

            if (len(test_cases) != 1):
                api_error(
                    'TC %s is not unique' % testcase_id
                )
                return

            # The result to return
            json_result = {
                '_type': 'response',
                'ok': True,
                'content': [
                    {
                        '_type': 'tc_basic',
                        'id': test_cases[0][0],
                        'objective': test_cases[0][1]
                    },
                    {
                        '_type': 'tc_implementation',
                        'implementation': test_cases[0][2]
                    }
                ]
            }

            # Here the process from ttproto core
            print(json.dumps(json_result))
            return

        # GET handler for the get_testcases uri
        # It will give to the gui the list of the test cases
        #
        elif url.path == '/api/v1/testcase_getList':

            # Send the header
            self.send_response(200)
            self.send_header("Content-Type", "application/json;charset=utf-8")
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Own function to clean the datas received
            raw_test_cases = analysis.get_implemented_testcases()
            clean_test_cases = []  # Dict of (tc_id, tc_desc)
            for raw_tc in raw_test_cases:
                clean_test_cases.append({
                    '_type': 'tc_basic',
                    'id': raw_tc[0],
                    'objective': raw_tc[1]
                })

            # The result to return
            json_result = {
                '_type': 'response',
                'ok': True,
                'content': clean_test_cases
            }

            # Just give the json representation of the test cases list
            print(json.dumps(json_result))
            return

        # GET handler for the get_protocols uri
        # It will give to the gui the list of the protocols implemented
        #
        elif url.path == '/api/v1/frames_getProtocols':

            # Send the header
            self.send_response(200)
            self.send_header("Content-Type", "application/json;charset=utf-8")
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # The result to return
            json_result = {
                '_type': 'response',
                'ok': True,
                'content': [
                    {
                        '_type': 'protocol',
                        'name': 'None',
                        'description': 'No particular protocol'
                    },
                    {
                        '_type': 'protocol',
                        'name': 'CoAP',
                        'description': 'CoAP protocol'
                    }
                ]
            }

            # Just give the json representation of the test cases list
            print(json.dumps(json_result))
            return

        # GET handler for the get_frame uri
        # It will allow a user to get a single frame from the previous pcap
        #
        # /param frame_id => The id of the wanted frame
        # /param token => The token of the corresponding pcap file
        #
        # /remark Maybe it will be better to give an id to testes, store them
        #         into databases and then add another param representing the
        #         id of the test.
        #         More than that, it will allow users to retrieve a passed test
        #         and share it.
        #
        elif url.path == '/api/v1/get_frame':

            # Send the header
            self.send_response(200)
            self.send_header("Content-Type", "application/json;charset=utf-8")
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the parameters
            params = parse_qs(url.query)
            try:

                # Correct execution
                if any((
                    len(params) != 2,
                    'frame_id' not in params,
                    'token' not in params,
                    len(params['frame_id']) != 1,
                    not params['frame_id'][0].isdigit(),
                    len(params['token']) != 1
                )):
                    raise

            # Catch errors (key mostly) or if wrong parameter
            except:
                api_error(
                    'Incorrects parameters expected \'?frame_id=[integer]&token=[string]\''
                )
                return

            # Format the id before passing it to the process function
            frame_id = int(params['frame_id'][0])
            token = params['token'][0]

            # Here the process from ttproto core
            json_result = {
                '_type': 'response',
                'ok': True,
                'content': [
                    {
                        '_type': 'token',
                        'value': token
                    },
                    {
                        '_type': 'frame',
                        'id': '',
                        'timestamp': '',
                        'error': '',
                        'protocol_stack': [
                            {
                                '_type': 'protocol',
                                'protocol': 'proto name',
                                'field_1_name': 'sth',
                                'field_2_name': 'sth_else'
                            }
                        ]
                    }
                ]
            }

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

        # POST handler for the testcase_analyse uri
        # It will allow users to analyse a pcap file corresponding to a TC
        #
        # \param pcap_file => The pcap file that we want to analyse
        # \param testcase_id => The id of the corresponding test case
        # \param token => The token previously provided
        # The pcap_file or the token is required, having both is also forbidden
        #
        if self.path == '/api/v1/testcase_analyse':

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the content type
            content_type = cgi.parse_header(self.headers['Content-Type'])
            content_type = content_type[0]

            # Check headers
            if any((
                content_type is None,
                content_type != 'multipart/form-data'
            )):
                api_error(
                    'POST format of \'multipart/form-data\' expected'
                )
                return

            # Get post values
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                keep_blank_values=True,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': content_type
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
                api_error(
                    'Expected POST=([pcap_file|token], testcase_id)'
                )
                return

            # Get the pcap file
            pcap_file = form.getvalue('pcap_file')
            timestamp=''
            if (pcap_file):

                # Path to save the file
                timestamp = time.strftime("%y%m%d_%H%M%S")
                pcap_path = os.path.join(
                    TMPDIR,
                    "%s_%04d.dump" % (timestamp, job_id)
                )

                # Write the pcap file to a temporary destination
                with open(pcap_path, 'wb') as f:
                    f.write(pcap_file)

            # Get the token
            token = form.getvalue('token')

            # Generate the token if none given
            if not token:
                token = hashlib.sha1(
                    str.encode((
                        "%s%s%04d%s" %
                        (
                            HASH_PREFIX,
                            timestamp,
                            job_id,
                            HASH_SUFFIX
                        )
                    ), encoding='utf-8')
                )
                token = base64.urlsafe_b64encode(token.digest()).decode()

            # Get the test case and its informations
            testcase_id = str(form.getvalue('testcase_id'))
            assert type(testcase_id)==str
            #if not testcase_id or testcase_id == '':
            #    testcase_id = ''

            # Try to get the test case the common way
            try:
                test_case = analysis.get_implemented_testcases(testcase_id)
            except FileNotFoundError:
                api_error(
                    'No test case with the id %s' % testcase_id
                )
                return

            # FIXME: Don't forget to remove this block when the bug is fixed
            except ImportError:
                os.chdir('../../..')
                # api_error(
                #     'TC %s found but a bug is to fix' % testcase_id
                # )
                test_cases = analysis.get_implemented_testcases()
                for tc in test_cases:
                    if tc[0] == testcase_id:
                        test_case = {
                            '_type': 'tc_basic',
                            'id': tc[0],
                            'objective': tc[1]
                        }

            # print(test_case)
            # if (len(test_case) != 1):
            #     api_error(
            #         'TC %s is not unique' % testcase_id
            #     )
            #     return

            # Get the result of the analysis
            analysis_results = analysis.analyse_file_rest_api(
                                pcap_path,
                                False,
                                None,
                                testcase_id,
                                'client'
                            )

            # Only take the first
            # TODO: Maybe change it to get many of them
            verdict = {
                '_type': 'verdict',
                'verdict': analysis_results[0][1],
                'description': test_case['objective'],
                'review_frames': []
            }

            # Prepare the result to return
            json_result = {
                '_type': 'response',
                'ok': True,
                'content': [
                    {
                        '_type': 'token',
                        'value': token
                    },
                    test_case,
                    verdict
                ]
            }

            # Here we will analyse the pcap file and get the results as json
            print(json.dumps(json_result))
            return

        # POST handler for the frames_dissect uri
        # It will allow users to analyse a pcap file corresponding to a TC
        #
        # \param pcap_file => The pcap file that we want to dissect
        # \param token => The token previously provided
        # \param protocol_selection => The protocol name (optional)
        # The pcap_file or the token is required, having both is also forbidden
        #
        elif self.path == '/api/v1/frames_dissect':

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the content type
            content_type = cgi.parse_header(self.headers['Content-Type'])
            content_type = content_type[0]

            # Check headers
            if any((
                content_type is None,
                content_type != 'multipart/form-data'
            )):
                api_error(
                    'POST format of \'multipart/form-data\' expected'
                )
                return

            # Get post values
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': content_type
                })

            # Check the parameters passed
            if any((
                len(form) not in [1, 2],
                all((  # None of the two required => Error
                    'pcap_file' not in form,
                    'token' not in form
                )),
                all((  # Both of them => Error
                    'pcap_file' in form,
                    'token' in form
                )),
                len(form) == 2 and 'protocol_selection' not in form
            )):
                api_error(
                    'Expected POST=([pcap_file|token], protocol_selection?)'
                )
                return

            # Check the protocol_selection value
            protocol_selection = form.getvalue('protocol_selection')

            # Get the pcap file
            pcap_file = form.getvalue('pcap_file')
            if (pcap_file):

                # Path to save the file
                timestamp = time.strftime("%y%m%d_%H%M%S")
                pcap_path = os.path.join(
                    TMPDIR,
                    "%s_%04d.dump" % (timestamp, job_id)
                )

                # Write the pcap file to a temporary destination
                with open(pcap_path, 'wb') as f:
                    f.write(pcap_file)

            # Get the token
            token = form.getvalue('token')

            # Generate the token if none given
            if not token:
                token = hashlib.sha1(
                    str.encode((
                        "%s%s%04d%s" %
                        (
                            HASH_PREFIX,
                            timestamp,
                            job_id,
                            HASH_SUFFIX
                        )
                    ), encoding='utf-8')
                )
                token = base64.urlsafe_b64encode(token.digest()).decode()

            # In function of the protocol asked
            # TODO: For the moment only one protocol, but later use a dict
            protocol = None
            if protocol_selection == 'CoAP':
                protocol = coap.CoAP

            # Prepare the result to return
            json_result = {
                '_type': 'response',
                'ok': True,
                'content': [
                    {
                        '_type': 'token',
                        'value': token
                    },
                    {
                        '_type': 'frame',
                        'id': 1,
                        'timestamp': 1456858700.521622,
                        'error': None,
                        'protocol_stack': [
                            {
                                '_type': 'protocol',
                                'Protocol': 'Ethernet',
                                'DestinationAddress': '18:1e:78:4e:03:10',
                                'SourceAddress': 'ac:bc:32:cd:f3:8b',
                                'Type': '0x0800',
                                'Trailer': 'b'''
                            },
                            {
                                '_type': 'protocol',
                                'Protocol': 'IPv4',
                                'Version': '4',
                                'HeaderLength': '5',
                                'TypeOfService': '0x00',
                                'TotalLength': '41',
                                'Identification': '0x5948',
                                'Reserved': '0',
                                'DontFragment': '0',
                                'MoreFragments': '0',
                                'FragmentOffset': '0',
                                'TimeToLive': '64',
                                'Protocol': '17',
                                'HeaderChecksum': '0xceee',
                                'SourceAddress': '192.168.1.17',
                                'DestinationAddress': '129.132.15.80',
                                'Options': 'b'''
                            },
                            {
                                '_type': 'protocol',
                                'Protocol': 'UDP',
                                'SourcePort': '65236',
                                'DestinationPort': '5683',
                                'Length': '21',
                                'Checksum': '0x16b8'
                            },
                            {
                                '_type': 'protocol',
                                'Protocol': 'CoAP',
                                'Version': '1',
                                'Type': '1',
                                'TokenLength': '2',
                                'Code': '1',
                                'MessageID': '0x3bf1',
                                'Token': 'b\'b\\xda\'',
                                'Payload': 'b''',
                                'Options': [
                                    {
                                        '_type': 'option',
                                        'Option': 'CoAPOptionUriPath',
                                        'Delta': '11',
                                        'Length': '4',
                                        'Value': 'test'
                                    },
                                    {
                                        '_type': 'option',
                                        'Option': 'CoAPOptionBlock2',
                                        'Delta': '12',
                                        'Length': '1',
                                        'Number': '0',
                                        'M': '0',
                                        'SizeExponent': '2'
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        '_type': 'frame',
                        'id': 2,
                        'timestamp': 1456858706.951686,
                        'error': None,
                        'protocol_stack': [
                            {
                                '_type': 'protocol',
                                'Protocol': 'Ethernet',
                                'DestinationAddress': 'ac:bc:32:cd:f3:8b',
                                'SourceAddress': '18:1e:78:4e:03:11',
                                'Type': '0x0800',
                                'Trailer': 'b'''
                            },
                            {
                                '_type': 'protocol',
                                'Protocol': 'IPv4',
                                'Version': '4',
                                'HeaderLength': '5',
                                'TypeOfService': '0x00',
                                'TotalLength': '90',
                                'Identification': '0x0000',
                                'Reserved': '0',
                                'DontFragment': '1',
                                'MoreFragments': '0',
                                'FragmentOffset': '0',
                                'TimeToLive': '43',
                                'Protocol': '17',
                                'HeaderChecksum': '0xfd05',
                                'SourceAddress': '129.132.15.80',
                                'DestinationAddress': '192.168.1.17',
                                'Options': 'b'''
                            },
                            {
                                '_type': 'protocol',
                                'Protocol': 'UDP',
                                'SourcePort': '5683',
                                'DestinationPort': '65236',
                                'Length': '70',
                                'Checksum': '0x1469'
                            },
                            {
                                '_type': 'protocol',
                                'Protocol': 'CoAP',
                                'Version': '1',
                                'Type': '1',
                                'TokenLength': '2',
                                'Code': '69',
                                'MessageID': '0xa312',
                                'Token': 'b\'b\\xda\'',
                                'Payload': 'b\'Type: 1 (NON)\\nCode: 1 (GET)\\nMID: 15345\\nToken: 62da\'',
                                'Options': [
                                    {
                                        '_type': 'option',
                                        'Option': 'CoAPOptionContentFormat',
                                        'Delta': '12',
                                        'Length': '0',
                                        'Value': '0'
                                    },
                                    {
                                        '_type': 'option',
                                        'Option': 'CoAPOptionMaxAge',
                                        'Delta': '2',
                                        'Length': '1',
                                        'Value': '30'
                                    },
                                    {
                                        '_type': 'option',
                                        'Option': 'CoAPOptionBlock2',
                                        'Delta': '9',
                                        'Length': '1',
                                        'Number': '0',
                                        'M': '0',
                                        'SizeExponent': '2'
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }

            # Here we will analyse the pcap file and get the results as json
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

    # ttproto API part
    cgitb.enable(display=0, logdir=LOGDIR)

# reopen_log_file(None, None)
#
# # log rotation
# # -> reopen the log file upon SIGHUP
# signal.signal(signal.SIGHUP, reopen_log_file)
#
# server=http.server.HTTPServer(("0.0.0.0", 2080), RequestHandler)
# while not __shutdown:
#     try:
#         l = log_file
#         server.handle_request()
#     except select.error:
#         # do not abort when we receive a signal
#         if l == log_file:
#             raise
#
#     if len(sys.argv) > 1:
#         break
