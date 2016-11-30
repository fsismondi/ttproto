#!/usr/bin/env python3
#
#   (c) 2012    Universite de Rennes 1
#
# Contact address: <t3devkit@irisa.fr>
#
#
# This software is governed by the CeCILL license under French law and
# abiding by the rules of distribution of free software.    You can  use,
# modify and/or redistribute the software under the terms of the CeCILL
# license as circulated by CEA, CNRS and INRIA at the following URL
# "http://www.cecill.info".
#
# As a counterpart to the access to the source code and  rights to copy,
# modify and redistribute granted by the license, users are provided only
# with a limited warranty  and the software's author,  the holder of the
# economic rights,  and the successive licensors    have only  limited
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

import sys, time, re, itertools, socket, urllib.parse, glob, inspect
from lib2to3.fixes.fix_print import parend_expr
from os import chdir, path, getcwd
from importlib import import_module

from ttproto.core.lib.readers.pcap import PcapReader
from ttproto.core.data import Data, Value
from ttproto.core.list import ListValue
from ttproto.core.packet import PacketValue


from ttproto.core.lib.ethernet import *
from ttproto.core.lib.encap import *

import ttproto.core.lib.inet.all
from ttproto.core.lib.inet.ipv4 import *
from ttproto.core.lib.inet.ipv6 import *
from ttproto.core.lib.inet.udp import *
from ttproto.core.lib.inet.coap import *
from ttproto.core.lib.inet.sixlowpan import *
from ttproto.core.lib.inet.sixlowpan_hc import *

from ttproto.core.lib.ieee802154 import *

from ttproto.core.xmlgen import XHTML10Generator
from ttproto.core.html_logger import HTMLLogger
from ttproto.utils.version_git import get_git_version

from collections import OrderedDict


# import the specifics for the protocol to be tested
from . import proto_specific

# small hack to allow participants running a server on non standard ports:
#import ttproto.core.lib.inet.udp
#for port in (5684, 5685, 5686, 5687, 5688, 5689):
#    ttproto.core.lib.inet.udp.udp_port_map[port] = CoAP


TOOL_VERSION = get_git_version()
TEST_VERSION = "td-coap4_&_IRISA"
TESTCASES_SUBDIR = '/ttproto/ts_coap/testcases'

# TODO abstract classes?
TestCase = proto_specific.CoAPTestcase
Tracker = proto_specific.CoAPTracker

class Resolver:
    __cache = {}

    def __new__ (cls, ip_addr):
        try:
            return cls.__cache[ip_addr]
        except KeyError:
            pass

        try:
            name = socket.gethostbyaddr (str (ip_addr))[0]
        except socket.herror:
            name = None

        cls.__cache[ip_addr] = name

        return name

    @classmethod
    def format (cls, ip_addr):
        name = cls (ip_addr)

        if name:
            return "%s (%s)" % (name, ip_addr)
        else:
            return ip_addr

class Frame:
    """

    """
    @classmethod
    def create_list (cls, pcap_frames):
        return list (cls (i, f) for i,f in zip (itertools.count(1), pcap_frames))

    def __init__ (self, id, pcap_frame):
        self.id = id
        self.ts, self.msg, self.exc = pcap_frame
        self.__extract_infos()

    def __repr__ (self):
        return "<Frame %3d: %s>" % (self.id, self.msg.summary())

    def __extract_infos (self):
        self.src    = None
        self.dst    = None
        self.coap   = None

        v = self.msg.get_value()
        while True:
            if isinstance (v, Ethernet) or isinstance (v, IPv6) or isinstance (v, IPv4):
                self.src = v["src"]
                self.dst = v["dst"]
                v = v["pl"]
                continue
            elif isinstance (v, UDP):
                if not isinstance (self.src, tuple):
                    self.src = self.src, v["sport"]
                    self.dst = self.dst, v["dport"]
                v = v["pl"]
                continue
            elif isinstance (v, CoAP):
                self.coap = v
            elif isinstance (v, Ieee802154):
                self.src = v["src"]
                self.dst = v["dst"]
                v = v["pl"]
                continue
            elif isinstance (v, SixLowpan) or isinstance (v, LinuxCookedCapture) or isinstance (v, NullLoopback):
                try:
                    v = v["pl"]
                    continue
                except KeyError:
                    pass

            break


def get_implemented_testcases(testcase_id = None, no_verbose = None):
    """
    :return:
    -List of descriptions of test cases
    Each element of the list is composed of:
        -tc_identifier
        -tc_objective
        -tc_sourcecode
    """

    testcases,_= import_testcases(testcase_id)
    ret = []
    for tc in testcases:
        if no_verbose:
            ret.append((tc.__name__, tc.get_objective(), ''))
        else:
            ret.append((tc.__name__ ,tc.get_objective(), inspect.getsource(tc)))
    return ret


def import_testcases(testcase_id = None):
    """
    Assumptions:
    -test cases are defined inside a file, each file contains only one test case
    -names of the file and class must match
    -all test cases must be named TD_*

    :param testcase_id:

    Imports test cases classes from TESTCASES_DIR named TD*
    Returns:
        tuple of list:
        ( testcases , obsoletes )
    """

    # TODO take a list as a param and return corresponding testcases classes respecting the order.
    SEARCH_STRING = 'td*.py'
    tc_plugins = {}
    testcases = []
    obsoletes = []


    prv_wd = getcwd()
    chdir( prv_wd + TESTCASES_SUBDIR )

    #  find files named "TD*" or testcase_id (if provided) in TESTCASES_DIR
    dir_list = glob.glob(SEARCH_STRING)
    modname_test_list = [path.basename(f)[:-3] for f in dir_list if path.isfile(f)]
    modname_test_list.sort()

    if testcase_id:
        if testcase_id.lower() in modname_test_list:
            modname_test_list = [testcase_id]

            # filename not found in dir
        else:
            # move back to the previously dir
            chdir(prv_wd)
            raise FileNotFoundError("Testcase : " + testcase_id + " couldn't be found")

    # import sorted list
    for modname in modname_test_list:
        # note that the module is always lower case and the plugin (class) is upper case (ETSI naming convention)
        tc_plugins[modname] = getattr(import_module(modname.lower()), modname.upper())
        if tc_plugins[modname].obsolete:
            obsoletes.append (tc_plugins[modname])
        else:
            testcases.append (tc_plugins[modname])

    # move back to the previously dir
    chdir(prv_wd)

    assert all (isinstance (t, type) and issubclass (t,TestCase) for t in testcases)

    if obsoletes:
        sys.stderr.write ("%d obsolete testcases:\n" % len (obsoletes))
        for tc_type in obsoletes:
            sys.stderr.write ("\t%s\n" % tc_type.__name__)

    return testcases , obsoletes


def analyse_file (filename):
    testcases, _ = import_testcases()
    # read the frame
    # TODO: filter uninteresting frames ? (to decrease the load)
    with Data.disable_name_resolution():
        frames = Frame.create_list (PcapReader (filename))

        for f in frames:
            print ("%5d %s" % (f.id, f.msg.summary()))

        # malformed frames
        malformed = list (filter ((lambda f: f.exc), frames))

        print ("\n%d malformed frames" % len (malformed))
        for f in malformed:
            print ("%5d %s" % (f.id, f.exc))

        tracker = Tracker (frames)
        conversations = tracker.conversations
        ignored = tracker.ignored_frames
    #   sys.exit(1)
    #   conversations, ignored = extract_coap_conversations (frames)

        print ("\n%d ignored frames" % len (ignored))
        for f in ignored:
            print ("%5d %s" % (f.id, f.msg.summary()))

        print ("\n%d CoAP conversations" % len (conversations))
        for t in conversations:
            print ("    ---- Conversation %d    %s ----" % (t.id, t.tag))
            for f in t:
                print ("    %5d %s" % (f.id, f.msg.summary()))

        conversations_by_pair = proto_specific.group_conversations_by_pair (conversations)

        print ("\nTestcase results")
        results_by_pair = {}
        for pair, conversations in conversations_by_pair.items():
            pair_results = []
    #       print (pair, conversations)
            print ("---- Pair  %s -> %s ----" % pair)
            for tc_type in testcases:
                print (" --- Testcase %s ---" % tc_type.__name__)
                tc_results = []
                for tr in conversations:
                    tc = tc_type (tr)
                    if tc.verdict:
                        print ("    -- Conversation %d -> %s --" % (tc.conversation.id, tc.verdict))
                        for line in tc.text.split("\n"):
                            print ("\t" + line)
                        tc_results.append (tc)
                pair_results.append (tc_results)

    #   print (pair_results)

reg_frame = re.compile ("<Frame  *(\d+):")
reg_verdict = re.compile (r"    \[ *([a-z]+) *\]")


# TODO make unitest for analyse!
def analyse_file_rest_api(filename, urifilter = False, exceptions = None, regex = None, profile = "client", verbose=False):
    """
    :param filename:
    :param urifilter:
    :param exceptions:
    :param regex:
    :param profile:
    :param verbose: boolean, if true method returns verdict description (which may be very verbose)
    :return: tuple

    example:
    [('TD_COAP_CORE_03', 'fail', [21, 22]), 'verdict description']

    NOTES:
     - allows multiple ocurrences of the testcase, returns as verdict:
            - fail: if at least one on the occurrences failed
            - inconclusive : if all ocurrences returned a inconv verdict
            - pass: all occurrences are inconclusive or at least one is PASS and the rest is inconclusive
    """
    testcases, _ = import_testcases(regex)
    my_testcases = [t for t in testcases if t.reverse_proxy == (profile == "reverse-proxy") ]

    if regex is not None:
        try:
            re_regex = re.compile (regex, re.I)
        except Exception as e:
            return "Error: regular expression %r is invalid (%s)" % (regex, e)

    my_testcases = list (filter ((lambda t: re_regex.search(t.__name__)), my_testcases))

    if not my_testcases:
        return "regular expression %r did not yield any testcase" % regex
    force = len (my_testcases) == 1

    with Data.disable_name_resolution():
        frames = Frame.create_list (PcapReader (filename))

        # malformed frames
        malformed = list (filter ((lambda f: f.exc), frames))
        tracker = Tracker (frames)
        conversations = tracker.conversations
        ignored = tracker.ignored_frames


        results = []

        conversations_by_pair = proto_specific.group_conversations_by_pair(conversations)
        results_by_pair = {}
        for pair, conversations in conversations_by_pair.items():
            pair_results = []
            for tc_type in my_testcases:
                tc_results = []

                # we run the testcase for each conversation, meaning that one type of TC can have more than one result!
                for tr in conversations:
                    tc = tc_type(tr, urifilter, force)
                    if tc.verdict:

                        tc_results.append(tc)

                        # remember the exception
                        if hasattr(tc, "exception") and exceptions is not None:
                            exceptions.append(tc)

                pair_results.append(tc_results)

        verdicts = None, "inconclusive", "pass", "fail", "error"
        for tc_type, tc_results in filter(lambda x: regex in x[0].__name__, zip(my_testcases, pair_results)):
            review_frames=[]
            v = 0
            for tc in tc_results:
                # all the failed frames for a TC, even if they are from different conversations!
                review_frames = tc.failed_frames

                new_v = verdicts.index(tc.verdict)
                if new_v > v:
                    v = new_v

            v_txt = verdicts[v]
            if v_txt is None:
                v_txt = "none"

            if verbose:
                results.append( (type(tc).__name__, v_txt, list(review_frames),tc.text))
            else:
                results.append((type(tc).__name__, v_txt, list(review_frames),''))
            # TODO clean list(review_frames)  tc.review_frames_log , tc.review_frames_log in module proto_specific

        return results


def analyse_file_html (filename, orig_name, urifilter = False, exceptions = None, regex = None, profile = "client"):
    """
    TODO
    Args:
        filename:
        orig_name:
        urifilter:
        exceptions:
        regex:
        profile:

    Returns:

    """
    testcases, _ = import_testcases()

    logger = HTMLLogger()

    with XHTML10Generator () as g:

        def log_text (text):
            if not isinstance (text, str):
                text = str (text)
            for line in text.split("\n"):
                mo = reg_frame.match (line)
                if mo:
                    g.a(href="#frame"+mo.group(1))(line + "\n")
                    continue
                mo = reg_verdict.match (line)
                if mo:
                    g.span (**{"class": mo.group(1)})(line)
                    g ("\n")
                elif line.endswith ("Mismatch"):
                    g.span (**{"class": "mismatch"})(line)
                    g ("\n")
                elif line.startswith ("Chaining to conversation "):
                    g ("\n")
                    g.span (**{"class": "chaining"})(line)
                    g ("\n")
                else:
                    g (line)
                    g ("\n")

        with g.head:
            g.title ("CoAP interoperability test results")
            g.meta (**{"http-equiv": "Content-Type", "content": "text/html; charset=utf-8"})

            g.style ("""
a {color: inherit; text-decoration: inherit}
.pass {color: green;}
.inconclusive {color: #e87500;}
.fail {color: red;}
.error {color: red;}
.mismatch {color: #803000;}
.chaining {color: #808080; font-style: italic;}
.bgpass {background-color: #B0FFB0;}
.bginconclusive {background-color: #FFB080;}
.bgfail {background-color: #FF9090;}
.bgerror {background-color: #FF9090;}
.bgnone {background-color: #FFFFB0;}
td {padding-left:15px; padding-right:15px; padding-top:3px; padding-bottom:3px;}
th {padding-left:15px; padding-right:15px; padding-top:10px; padding-bottom:10px;}
table {border: 1px solid; border-spacing: 0px; }
""", type = "text/css")

        g.h1 ("CoAP interoperability test results")

        g.pre("""Tool version:   %s
File:           %s
Date:           %s
URI filter:     %s
Regex:      %r
""" % ( TOOL_VERSION,
    (orig_name if orig_name else "(unknown)"),
    time.strftime ("%a, %d %b %Y %T %z"),
    ("enabled" if urifilter else "disabled"),
    regex),

    style = "line-height: 150%;")

        my_testcases = [t for t in testcases if t.reverse_proxy == (profile == "reverse-proxy") ]

        if regex is not None:
            try:
                re_regex = re.compile (regex, re.I)
            except Exception as e:
                g.b("Error: ")
                g("regular expression %r is invalid (%s)" % (regex, e))
                return

            my_testcases = list (filter ((lambda t: re_regex.search(t.__name__)), my_testcases))

            if not my_testcases:
                g.b("Warning: ")
                g("regular expression %r did not yield any testcase" % regex)


        force = len (my_testcases) == 1

        g.h2 ("Summary")
        with g.table(id="summary", border=1): # FIXME: bug xmlgen
            pass

        with Data.disable_name_resolution():
            frames = Frame.create_list (PcapReader (filename))

            g.h2("File content (%d frames)" % len (frames))
            with g.pre:
                for f in frames:
                    log_text (f)

            # malformed frames
            malformed = list (filter ((lambda f: f.exc), frames))

            g.h2("Malformed frames (%d)" % len (malformed))
            with g.pre:
                for f in malformed:
                    log_text (f)
                    g(" %s\n" % f.exc)

            tracker = Tracker (frames)
            conversations = tracker.conversations
            ignored = tracker.ignored_frames
        #   sys.exit(1)
        #   conversations, ignored = extract_coap_conversations (frames)

            g.h2 ("Ignored frames (%d)" % len (ignored))
            with g.pre:
                for f in ignored:
                    log_text (f)

            g.h2 ("CoAP conversations (%d)" % len (conversations))
            for t in conversations:
                g.h3 ("Conversation %d %s" % (t.id, t.tag))
                with g.pre:
                    for f in t:
                        log_text (f)

            conversations_by_pair = proto_specific.group_conversations_by_pair (conversations)

            g.h2 ("Testcase results")

            with g.script (type="text/javascript"):
                g('''
var t=document.getElementById("summary");
var r;
var c;
var a;
''')
            results_by_pair = {}
            for pair, conversations in conversations_by_pair.items():
                pair_results = []
                pair_txt = "%s vs %s" % tuple (map (Resolver.format, pair))
                g.h3 (pair_txt)
                for tc_type in my_testcases:
                    tc_results = []
                    g.a(name="%x" % id(tc_results))
                    g.h4 ("Testcase %s  -  %s" % (tc_type.__name__, tc_type.get_objective()))
                    for tr in conversations:
                        tc = tc_type (tr, urifilter, force)
                        if tc.verdict:
                            with g.h5:
                                g ("Conversation %d -> "% tc.conversation.id)
                                g.span (tc.verdict, **{"class": tc.verdict})
                            with g.pre:
                                log_text (tc.text)

                            tc_results.append (tc)

                            # remember the exception
                            if hasattr (tc, "exception") and exceptions is not None:
                                exceptions.append (tc)

                    pair_results.append (tc_results)

                with g.script (type="text/javascript"):

                    g('''
r=t.insertRow(-1);
c=document.createElement ("th");
c.innerHTML=%s;
c.colSpan=4;
r.appendChild(c);
''' % repr (pair_txt))
                    verdicts = None, "inconclusive", "pass", "fail", "error"
                    for title, func in (
                            ("ETSI interoperability test scenarios",(lambda x: "IRISA" not in x[0].__name__)),
                            ("IRISA interoperability test scenarios",(lambda x: "IRISA" in x[0].__name__))
                        ):
                        g('''
r=t.insertRow(-1);
c=document.createElement ("th");
c.innerHTML=%s;
c.colSpan=4;
r.appendChild(c);
''' % repr(title))
                        for tc_type, tc_results in filter(func,zip(my_testcases,pair_results)):
                            v = 0
                            for tc in tc_results:
                                new_v = verdicts.index (tc.verdict)
                                if new_v > v:
                                    v = new_v
                            v_txt = verdicts[v]
                            if v_txt is None:
                                v_txt = "none"
#TODO: factorise that w/ a function
                            g('''
r=t.insertRow(-1);

a=document.createElement ("a")
a.href=("#%x")
a.innerHTML=%s
r.insertCell(-1).appendChild(a);

a=document.createElement ("a")
a.href=("#%x")
a.innerHTML=%s
r.insertCell(-1).appendChild(a);

a=document.createElement ("a")
a.href=("#%x")
a.innerHTML=%s
r.insertCell(-1).appendChild(a);

a=document.createElement ("a")
a.href=("#%x")
a.innerHTML=%s
c=r.insertCell(-1)
c.appendChild(a);
c.className=%s;
''' % (
                                id (tc_results),
                                repr (tc_type.__name__),
                                id (tc_results),
                                repr (tc_type.get_objective()),
                                id (tc_results),
                                repr ("%d occurence(s)" % len (tc_results)),
                                id (tc_results),
                                repr(v_txt),
                                repr("bg" + v_txt),
                            ))


                    """
                    pair_results = []
                    g.h3("%s vs %s" % pair)
                    for tc_type in my_testcases:
                        g.h4 ("Testcase %s" % tc_type.__name__)
                        tc_results = []
                        for tr in conversations:
                            tc = tc_type (tr)
                            if tc.verdict:
                                with g.h5:
                                    g ("Conversation %d -> "% tc.conversation.id)
                                    g.span (tc.verdict, **{"class": tc.verdict})
                                with g.pre:
                                    log_text (tc.text)

                                tc_results.append (tc)

                        pair_results.append (tc_results)
                """

            g.h2 ("Frames details")

            for f in frames:
                with g.pre:
                    g.a(name = "frame%d" % f.id)
                    g.b()("\n%s\n\n" % f)

                    b = f.msg.get_binary()
                    for offset in range(0, len(b), 16):
                        values = ["%02x" % v for v in b[offset:offset+16]]
                        if len(values) > 8:
                            values.insert (8, " ")

                        g("         %04x     %s\n" % (offset, " ".join(values)))
                logger.display_value (g, f.msg.get_value())
                g(" ")
                g.br()
                g.hr()


def basic_dissect_pcap_to_list (filename, protocol_selection=None):
    """
    :param filename: filename of the pcap file to be dissected
    :param protocol_selection:  protocol class for filtering purposes (inheriting from packet Value)
    :return: list of tuples with basic info about frames:
    [
        (13, '[127.0.0.1                        -> 127.0.0.1                       ] CoAP [CON 38515] GET /test'),
        (14, '[127.0.0.1                        -> 127.0.0.1                       ] CoAP [ACK 38515] 2.05 Content '),
        (21, '[127.0.0.1                        -> 127.0.0.1                       ] CoAP [CON 38516] PUT /test'),
        (22, '[127.0.0.1                        -> 127.0.0.1                       ] CoAP [ACK 38516] 2.04 Changed ')]
    ]

    """
    # read the frame
    # TODO: filter uninteresting frames ? (to decrease the load)
    with Data.disable_name_resolution():
        frames = Frame.create_list (PcapReader (filename))
        response=[]

        # content of the response, TODO make this generic for any protocol
        if protocol_selection and protocol_selection is CoAP:
            selected_frames = [f for f in frames if f.coap]
        else:
            selected_frames = frames

        for f in selected_frames:
                response.append ((f.id , f.msg.summary()))
        # malformed frames
        # malformed = list (filter ((lambda f: f.exc), frames))
    return response


def value_to_list(l: list, value: Value, extra_data=None, layer_dict:dict=None, is_option=False):

    # points to packet
    if isinstance(value, PacketValue):

        od = OrderedDict()

        if is_option:
            od['Option'] = value.get_variant().__name__
        else:
            od['_type'] = 'protocol'
            od['_protocol'] = value.get_variant().__name__

        l.append(od)

        i = 0
        for f in value.get_variant().fields():
            value_to_list(l, value[i], f.name, od)
            i += 1

    # TODO test this
    elif isinstance(value, ListValue):
        prot_options = []
        for i in range(0, len(value)):
            value_to_list(prot_options, value[i], is_option=True)
        layer_dict['Options'] = prot_options

    # it's a field
    else:
        layer_dict[extra_data] = str(value)


def dissect_pcap_to_list(filename, protocol_selection=None):
    """
    :param filename: filename of the pcap file to be dissected
    :param protocol_selection:  protocol class for filtering purposes (inheriting from packet Value)
    :return: List of frames (frames as Ordered Dicts)
    """

    if protocol_selection:
        assert issubclass(protocol_selection, PacketValue)

    frame_list = []

    # for speeding up the process
    with Data.disable_name_resolution():

        frames = Frame.create_list(PcapReader(filename))

        for f in frames:

            # if we are filtering and frame doesnt contain protocol
            # then skip frame
            # TODO make this generic for any type of protocol
            if protocol_selection and not f.coap:
                pass
            else:
                frame = OrderedDict()
                frame['_type'] = 'frame'
                frame['id'] = f.id
                frame['timestamp'] = f.ts
                frame['error'] = f.exc
                frame['protocol_stack'] = []
                value_to_list(frame['protocol_stack'], f.msg.get_value())
                frame_list.append(frame)
    return frame_list


################################################################################
# Main()
################################################################################

if __name__ == "__main__":

    import pprint,json
    PCAP_test2 = getcwd()+ "/tests/test_dumps/coap/TD_COAP_CORE_01_PASS.pcap"
    PCAP_test3 = getcwd() + "/tests/test_dumps/coap/coap_get_migled_with_tcp_traffic.pcap"



    #analyse_file(PCAP_test3)

    #get test case implementation
    #a= get_implemented_testcases('td_coap_core_01')
    #for f in a:
    #    print(a[0][2])

    #print(analyse_file_rest_api(PCAP_test2,False,None,"TD_COAP_CORE_17","client"))

    #print(dissect_pcap_to_list(PCAP_test3, None))
    #print(type(basic_dissect_pcap_to_list(PCAP_test3, None)))
    #print(basic_dissect_pcap_to_list(PCAP_test3, CoAP))

    print('************************')
    print('**API** ')
    print('************************')
    #print(basic_dissect_pcap_to_list(PCAP_test3, CoAP))
    print(analyse_file_rest_api(PCAP_test3, False, None, "TD_COAP_CORE_03", "client",True))
    #print(analyse_file_rest_api(PCAP_test3, False, None, "", "client",False))
    #print(analyse_file_rest_api(PCAP_error,None,None,"TD_COAP_CORE_01","client"))

    #a= get_implemented_testcases('td_coap_coreasd_01')
    #for f in a:
    #    print(a)
