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

import sys, time, re, itertools, socket, urllib.parse

from ttproto.core.lib.ports.pcap import PcapReader
from ttproto.core.data import Data

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

#import the specifics for the protocol to be tested
from . import proto_specific

# small hack to allow participants running a server on non standard ports:
#import ttproto.core.lib.inet.udp
#for port in (5684, 5685, 5686, 5687, 5688, 5689):
#    ttproto.core.lib.inet.udp.udp_port_map[port] = CoAP


TOOL_VERSION = get_git_version()

TEST_VERSION = "td-coap4_&_IRISA"

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


def get_testcases():
    """
    Imports test cases classes from TESTCASES_DIR
    Returns:
        tuple of lists:

        ( testcases , obsoletes )
    """

    # TODO take a list as a param and return corresponding testcases classes respecting the order.

    TESTCASES_SUBDIR = '/ttproto/ts_coap/testcases'
    from os import chdir, path, getcwd
    import glob

    tc_plugins = {}
    testcases = []
    obsoletes = []

    prv_wd = getcwd()

    # find files named "TD*" in TESTCASES_DIR
    chdir(prv_wd + TESTCASES_SUBDIR)
    dir_list = glob.glob('td*.py')
    modname_test_list = [path.basename(f)[:-3] for f in dir_list if
                                                         path.isfile(f)]

    modname_test_list.sort()
    # import sorted list
    for modname in modname_test_list:
        tc_plugins[modname] = getattr(__import__(modname,
                                                 fromlist=[modname.upper()]),
                                      modname.upper())
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
    testcases, _ = get_testcases()
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


def dissect_frames_json (filename):

    import json
    json_response=''

    # read the frame
    # TODO: filter uninteresting frames ? (to decrease the load)
    with Data.disable_name_resolution():
        frames = Frame.create_list (PcapReader (filename))
        response={}
        for f in frames:
            response[f.id] = [f.msg.summary() , f.msg.display()]
            print ("%5d %s" % (f.id, f.msg.summary()))
        json_response = json.dumps(response, indent = 4)
        # malformed frames
        malformed = list (filter ((lambda f: f.exc), frames))

        print ("\n%d malformed frames" % len (malformed))
        for f in malformed:
            print ("%5d %s" % (f.id, f.exc))

    #     tracker = Tracker (frames)
    #     conversations = tracker.conversations
    #     ignored = tracker.ignored_frames
    # #   sys.exit(1)
    # #   conversations, ignored = extract_coap_conversations (frames)
    #
    #     print ("\n%d ignored frames" % len (ignored))
    #     for f in ignored:
    #         print ("%5d %s" % (f.id, f.msg.summary()))
    #
    #     print ("\n%d CoAP conversations" % len (conversations))
    #     for t in conversations:
    #         print ("    ---- Conversation %d    %s ----" % (t.id, t.tag))
    #         for f in t:
    #             print ("    %5d %s" % (f.id, f.msg.summary()))
    #
    #     conversations_by_pair = proto_specific.group_conversations_by_pair (conversations)

    #     print ("\nTestcase results")
    #     results_by_pair = {}
    #     for pair, conversations in conversations_by_pair.items():
    #         pair_results = []
    # #       print (pair, conversations)
    #         print ("---- Pair  %s -> %s ----" % pair)
    #         for tc_type in testcases:
    #             print (" --- Testcase %s ---" % tc_type.__name__)
    #             tc_results = []
    #             for tr in conversations:
    #                 tc = tc_type (tr)
    #                 if tc.verdict:
    #                     print ("    -- Conversation %d -> %s --" % (tc.conversation.id, tc.verdict))
    #                     for line in tc.text.split("\n"):
    #                         print ("\t" + line)
    #                     tc_results.append (tc)
    #             pair_results.append (tc_results)

    #   print (pair_results)
    return json_response



reg_frame = re.compile ("<Frame  *(\d+):")
reg_verdict = re.compile (r"    \[ *([a-z]+) *\]")
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
    testcases, _ = get_testcases()

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
.inconc {color: #e87500;}
.fail {color: red;}
.error {color: red;}
.mismatch {color: #803000;}
.chaining {color: #808080; font-style: italic;}
.bgpass {background-color: #B0FFB0;}
.bginconc {background-color: #FFB080;}
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
                    g.a(name="%x" % id(tc_results));
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
                    verdicts = None, "inconc", "pass", "fail", "error"
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
                            if v_txt == None:
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


def analyse_file_rest_api(filename, orig_name, urifilter = False, exceptions = None, regex = None, profile = "client"):
    testcases, _ = get_testcases()
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
        #   sys.exit(1)
        #   conversations, ignored = extract_coap_conversations (frames)
        conversations_by_pair = proto_specific.group_conversations_by_pair (conversations)
        results_by_pair = {}
        results = []
        #TODO implement this more efficiently
        for pair, conversations in conversations_by_pair.items():
            pair_results = []
            pair_txt = "%s vs %s" % tuple (map (Resolver.format, pair))
            for tc_type in my_testcases:
                tc_results = []
                for tr in conversations:
                    tc = tc_type (tr, urifilter, force)
                    if tc.verdict:
                        tc_results.append (tc)
                        results.append((type(tc).__name__,tc.verdict))
                        # remember the exception
                    pair_results.append (tc_results)

        return results

#
# def analyse_file_json (filename, orig_name, urifilter = False, exceptions = None, regex = None, profile = "client"):
#     """
#     TODO
#     Args:
#         filename:
#         orig_name:
#         urifilter:
#         exceptions:
#         regex:
#         profile:
#
#     Returns:
#
#     """
#     testcases, _ = get_testcases()
#
#     class json_verdict:
#         def append
#
#
#     with XHTML10Generator () as g:
#
#         def log_text (text):
#             if not isinstance (text, str):
#                 text = str (text)
#             for line in text.split("\n"):
#                 mo = reg_frame.match (line)
#                 if mo:
#                     g.a(href="#frame"+mo.group(1))(line + "\n")
#                     continue
#                 mo = reg_verdict.match (line)
#                 if mo:
#                     g.span (**{"class": mo.group(1)})(line)
#                     g ("\n")
#                 elif line.endswith ("Mismatch"):
#                     g.span (**{"class": "mismatch"})(line)
#                     g ("\n")
#                 elif line.startswith ("Chaining to conversation "):
#                     g ("\n")
#                     g.span (**{"class": "chaining"})(line)
#                     g ("\n")
#                 else:
#                     g (line)
#                     g ("\n")
#
#         with g.head:
#             g.title ("CoAP interoperability test results")
#             g.meta (**{"http-equiv": "Content-Type", "content": "text/html; charset=utf-8"})
#
#             g.style ("""
# a {color: inherit; text-decoration: inherit}
# .pass {color: green;}
# .inconc {color: #e87500;}
# .fail {color: red;}
# .error {color: red;}
# .mismatch {color: #803000;}
# .chaining {color: #808080; font-style: italic;}
# .bgpass {background-color: #B0FFB0;}
# .bginconc {background-color: #FFB080;}
# .bgfail {background-color: #FF9090;}
# .bgerror {background-color: #FF9090;}
# .bgnone {background-color: #FFFFB0;}
# td {padding-left:15px; padding-right:15px; padding-top:3px; padding-bottom:3px;}
# th {padding-left:15px; padding-right:15px; padding-top:10px; padding-bottom:10px;}
# table {border: 1px solid; border-spacing: 0px; }
# """, type = "text/css")
#
#         g.h1 ("CoAP interoperability test results")
#
#         g.pre("""Tool version:   %s
# File:           %s
# Date:           %s
# URI filter:     %s
# Regex:      %r
# """ % ( TOOL_VERSION,
#     (orig_name if orig_name else "(unknown)"),
#     time.strftime ("%a, %d %b %Y %T %z"),
#     ("enabled" if urifilter else "disabled"),
#     regex),
#
#     style = "line-height: 150%;")
#
#         my_testcases = [t for t in testcases if t.reverse_proxy == (profile == "reverse-proxy") ]
#
#         if regex is not None:
#             try:
#                 re_regex = re.compile (regex, re.I)
#             except Exception as e:
#                 g.b("Error: ")
#                 g("regular expression %r is invalid (%s)" % (regex, e))
#                 return
#
#             my_testcases = list (filter ((lambda t: re_regex.search(t.__name__)), my_testcases))
#
#             if not my_testcases:
#                 g.b("Warning: ")
#                 g("regular expression %r did not yield any testcase" % regex)
#
#
#         force = len (my_testcases) == 1
#
#         g.h2 ("Summary")
#         with g.table(id="summary", border=1): # FIXME: bug xmlgen
#             pass
#
#         with Data.disable_name_resolution():
#             frames = Frame.create_list (PcapReader (filename))
#
#             g.h2("File content (%d frames)" % len (frames))
#             with g.pre:
#                 for f in frames:
#                     log_text (f)
#
#             # malformed frames
#             malformed = list (filter ((lambda f: f.exc), frames))
#
#             g.h2("Malformed frames (%d)" % len (malformed))
#             with g.pre:
#                 for f in malformed:
#                     log_text (f)
#                     g(" %s\n" % f.exc)
#
#             tracker = Tracker (frames)
#             conversations = tracker.conversations
#             ignored = tracker.ignored_frames
#         #   sys.exit(1)
#         #   conversations, ignored = extract_coap_conversations (frames)
#
#             g.h2 ("Ignored frames (%d)" % len (ignored))
#             with g.pre:
#                 for f in ignored:
#                     log_text (f)
#
#             g.h2 ("CoAP conversations (%d)" % len (conversations))
#             for t in conversations:
#                 g.h3 ("Conversation %d %s" % (t.id, t.tag))
#                 with g.pre:
#                     for f in t:
#                         log_text (f)
#
#             conversations_by_pair = proto_specific.group_conversations_by_pair (conversations)
#
#             g.h2 ("Testcase results")
#
#             with g.script (type="text/javascript"):
#                 g('''
# var t=document.getElementById("summary");
# var r;
# var c;
# var a;
# ''')
#             results_by_pair = {}
#             for pair, conversations in conversations_by_pair.items():
#                 pair_results = []
#                 pair_txt = "%s vs %s" % tuple (map (Resolver.format, pair))
#                 g.h3 (pair_txt)
#                 for tc_type in my_testcases:
#                     tc_results = []
#                     g.a(name="%x" % id(tc_results));
#                     g.h4 ("Testcase %s  -  %s" % (tc_type.__name__, tc_type.get_objective()))
#                     for tr in conversations:
#                         tc = tc_type (tr, urifilter, force)
#                         if tc.verdict:
#                             with g.h5:
#                                 g ("Conversation %d -> "% tc.conversation.id)
#                                 g.span (tc.verdict, **{"class": tc.verdict})
#                             with g.pre:
#                                 log_text (tc.text)
#
#                             tc_results.append (tc)
#
#                             # remember the exception
#                             if hasattr (tc, "exception") and exceptions is not None:
#                                 exceptions.append (tc)
#
#                     pair_results.append (tc_results)
#
#                 with g.script (type="text/javascript"):
#
#                     g('''
# r=t.insertRow(-1);
# c=document.createElement ("th");
# c.innerHTML=%s;
# c.colSpan=4;
# r.appendChild(c);
# ''' % repr (pair_txt))
#                     verdicts = None, "inconc", "pass", "fail", "error"
#                     for title, func in (
#                             ("ETSI interoperability test scenarios",(lambda x: "IRISA" not in x[0].__name__)),
#                             ("IRISA interoperability test scenarios",(lambda x: "IRISA" in x[0].__name__))
#                         ):
#                         g('''
# r=t.insertRow(-1);
# c=document.createElement ("th");
# c.innerHTML=%s;
# c.colSpan=4;
# r.appendChild(c);
# ''' % repr(title))
#                         for tc_type, tc_results in filter(func,zip(my_testcases,pair_results)):
#                             v = 0
#                             for tc in tc_results:
#                                 new_v = verdicts.index (tc.verdict)
#                                 if new_v > v:
#                                     v = new_v
#                             v_txt = verdicts[v]
#                             if v_txt == None:
#                                 v_txt = "none"
# #TODO: factorise that w/ a function
#                             g('''
# r=t.insertRow(-1);
#
# a=document.createElement ("a")
# a.href=("#%x")
# a.innerHTML=%s
# r.insertCell(-1).appendChild(a);
#
# a=document.createElement ("a")
# a.href=("#%x")
# a.innerHTML=%s
# r.insertCell(-1).appendChild(a);
#
# a=document.createElement ("a")
# a.href=("#%x")
# a.innerHTML=%s
# r.insertCell(-1).appendChild(a);
#
# a=document.createElement ("a")
# a.href=("#%x")
# a.innerHTML=%s
# c=r.insertCell(-1)
# c.appendChild(a);
# c.className=%s;
# ''' % (
#                                 id (tc_results),
#                                 repr (tc_type.__name__),
#                                 id (tc_results),
#                                 repr (tc_type.get_objective()),
#                                 id (tc_results),
#                                 repr ("%d occurence(s)" % len (tc_results)),
#                                 id (tc_results),
#                                 repr(v_txt),
#                                 repr("bg" + v_txt),
#                             ))
#
#
#                     """
#                     pair_results = []
#                     g.h3("%s vs %s" % pair)
#                     for tc_type in my_testcases:
#                         g.h4 ("Testcase %s" % tc_type.__name__)
#                         tc_results = []
#                         for tr in conversations:
#                             tc = tc_type (tr)
#                             if tc.verdict:
#                                 with g.h5:
#                                     g ("Conversation %d -> "% tc.conversation.id)
#                                     g.span (tc.verdict, **{"class": tc.verdict})
#                                 with g.pre:
#                                     log_text (tc.text)
#
#                                 tc_results.append (tc)
#
#                         pair_results.append (tc_results)
#                 """
#
#             g.h2 ("Frames details")
#
#             for f in frames:
#                 with g.pre:
#                     g.a(name = "frame%d" % f.id)
#                     g.b()("\n%s\n\n" % f)
#
#                     b = f.msg.get_binary()
#                     for offset in range(0, len(b), 16):
#                         values = ["%02x" % v for v in b[offset:offset+16]]
#                         if len(values) > 8:
#                             values.insert (8, " ")
#
#                         g("         %04x     %s\n" % (offset, " ".join(values)))
#                 logger.display_value (g, f.msg.get_value())
#                 g(" ")
#                 g.br()
#                 g.hr()

if __name__ == "__main__":

    #get_testcases()
    #print(dir())
    #print(globals())
    analyse_file (sys.argv[1])
    a = dissect_frames_json(sys.argv[1])
    print ("return values")
    print (type(a))
    print (a)

