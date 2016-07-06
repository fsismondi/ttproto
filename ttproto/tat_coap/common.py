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

import traceback
import sys
import time
import re
import socket

from .data import *
from contextlib import contextmanager
from lib2to3.fixes.fix_print import parend_expr
from ttproto.core.analyzer import TestCase, is_verdict
from ttproto.core.dissector import Frame
from ttproto.core.packet import PacketValue
from ttproto.core.xmlgen import XHTML10Generator
from ttproto.core.list import ListValue
from ttproto.core.templates import All, Not
from ttproto.core.typecheck import *
from ttproto.core.lib.all import *
from ttproto.utils.version_git import get_git_version
from ttproto.core.lib.ports.pcap import PcapReader
from urllib import parse

RESPONSE_TIMEOUT = 2
RESPONSE_RANDOM_FACTOR = 1.5
MAX_RETRANSMIT = 4

MAX_TIMEOUT = 10 + round(
        (RESPONSE_TIMEOUT * RESPONSE_RANDOM_FACTOR) * 2**MAX_RETRANSMIT
    )


TOOL_VERSION = get_git_version()
TEST_VERSION = "td-coap4_&_IRISA"


def duct_tape(frame):
    frame.src = None
    frame.dst = None

    v = frame.get_value()
    frame.ts = frame.get_timestamp()
    while True:
        if any((
            isinstance(v, Ethernet),
            isinstance(v, IPv6),
            isinstance(v, IPv4)
        )):
            frame.src = v["src"]
            frame.dst = v["dst"]
            v = v["pl"]
            continue
        elif isinstance(v, UDP):
            if not isinstance(frame.src, tuple):
                frame.src = frame.src, v["sport"]
                frame.dst = frame.dst, v["dport"]
            v = v["pl"]
            continue
        elif isinstance(v, CoAP):
            frame.coap = v
        elif isinstance(v, Ieee802154):
            frame.src = v["src"]
            frame.dst = v["dst"]
            v = v["pl"]
            continue
        elif any((
            isinstance(v, SixLowpan),
            isinstance(v, LinuxCookedCapture),
            isinstance(v, NullLoopback)
        )):
            try:
                v = v["pl"]
                continue
            except KeyError:
                pass

        break


class CoAPConversation(list):
    """
    Class to represent a CoAP conversation
    """

    @typecheck
    def __init__(self, request_frame: Frame):
        """
        Initialize a coap conversation using a request frame

        :param request_frame: The request frame to initialize the conversation.
                              This frame has to be a request or a ping frame.
        :type request_frame: Frame
        """

        # Check that there si a CoAP layer in the frame
        assert CoAP in request_frame

        # Check that the frame is a normal or a ping request
        assert any((
            request_frame[CoAP].is_request(),
            all((
                request_frame[CoAP]["code"] == 0,
                request_frame[CoAP]["type"] == 0
            ))
        ))

        # Generate the tag of this conversation (src, dst) or (dst, src)
        self.tag = self.gen_tag(request_frame)
        # self.append (request_frame)
        # self.update_timeout (request_frame)

        # Define the 2 entities @ of this conversation
        self.client = request_frame.src[0]
        self.server = request_frame.dst[0]

    @typecheck
    def update_timeout(self, request_frame: Frame):
        """
        Put the timeout of this conversation, this function is to check at the
        end that the conversation is valid in order to take or not take it into
        account

        :param request_frame: The request frame which has the timestamp of the
                              beginning of the conversation
        :type request_frame: Frame
        """
        self.timeout = request_frame.ts + MAX_TIMEOUT

    @typecheck
    def __hash__(self) -> int:
        """
        Generate an unique id for this conversation

        :return: Unique conversation id
        :rtype: int
        """
        return id(self)

    @typecheck
    def __bool__(self) -> bool:
        """
        Function to make the checking of this object as returning true

        :return: True everytime we check this object
        :rtype: bool

        .. note:: Normally Python should always return "True" when checking an
                  object which is not None. Maybe this should be removed.
        """
        return True

    @staticmethod
    @typecheck
    def gen_tag(frame: Frame) -> ((Value, int), (Value, int)):
        """
        Generate a tag from a frame

        :param frame: The frame from which we will generate the tag
        :type frame: Frame

        :return: The tag of this conversation
                 - ((src_addr, src_port), (dst_addr, dst_port)) for a request
                 - ((dst_addr, dst_port), (src_addr, src_port)) for a response
        :rtype: ((Value, int), (Value, int))
        """
        assert CoAP in frame

        if frame[CoAP].is_request():
            return frame.src, frame.dst
        else:
            return frame.dst, frame.src


class CoAPTestcase(TestCase):
    """
    The test case extension representing a CoAP test case
    """

    reverse_proxy = False

    class Stop(Exception):
        pass

    @typecheck
    def __init__(self, frame_list: list_of(Frame)):
        """
        Initialize a test case, the only thing that it needs for
        interoperability testing is a list of frame

        :param frame_list: The list of frames to analyze
        :type frame_list: [Frame]
        """
        super().__init__(frame_list)

        # Prepare the parameters
        self.__conversations = []
        self.__text = ''
        # self.failed_frames = set()
        # self.review_frames_log = []
        # try:
        # self.__current_conversation = self.conversations
        # self.__iter = iter(self.__current_conversation)
        # self.next()

        # self.run()

        # Ensure we're at the end of the communication
        # try:
        #     self.log(next(self.__iter))
        #     self.setverdict("inconc", "unexpected frame")
        # except StopIteration:
        #     pass

        # except self.Stop:
        #     # ignore this testcase result if the first frame gives an inconc
        #     # verdict
        #     if all((
        #         self.__verdict.get_value() == "inconc",
        #         self.frame == self.conversation[0]
        #     )):
        #         # no match
        #         self.verdict = None

        # except Exception:
        #     if self.__iter:
        #         self.setverdict("error", "unhandled exception")
        #         self.exception = traceback.format_exc()
        #         self.log(self.exception)

        # assert self.verdict in self.__verdicts

    @typecheck
    def match(self, verdict: is_verdict = 'inconc', msg: str = '', *args):
        """
        Abstract function to match a packet value with a template

        :param verdict: The verdict to put if it matches
        :param msg: The message to associate with the verdict
        :param args: More arguments if needed into implementations
        :type verdict: str
        :type msg: str
        :type args: tuple
        """
        raise NotImplementedError

    def next_frame(self):
        """
        Switch to the next frame
        """
        raise NotImplementedError

    @typecheck
    def log(self, msg: str):
        """
        Log a message

        :param msg: The message to log
        :type msg: str
        """
        text = str(msg)
        self.text += text if text.endswith("\n") else (text + "\n")
        self.review_frames_log.append(text)

    @classmethod
    @typecheck
    def get_objective(self) -> str:
        """
        Get the objective of this test case

        :return: The objective of this test case
        :rtype: str

        .. note:: Find a cleaner way to do this
        """
        if self.__doc__:
            ok = False
            for line in self.__doc__.splitlines():
                if ok:
                    return line
                if line == "Objective:":
                    ok = True
        return ""

    @typecheck
    def set_verdict(self, verdict: is_verdict, msg: str = ''):
        """
        Update the current verdict of the current test case

        :param verdict: The new verdict
        :param msg: The message to associate with the verdict
        :type verdict: str
        :type msg: str
        """
        if all((
            self._verdict.get_value() == 'none',
            verdict == 'inconc',
            not self.force
        )):
            raise self.Stop()

        # Update the verdict
        self._verdict.update(verdict, msg)

        # TODO: Check that the log function will be used like this
        self.log("  [%s] %s" % (format(v, "^6s"), text))

    @typecheck
    def pre_process(self) -> list_of(Frame):
        """
        Function for each TC to preprocess its list of frames

        :return: The list of ignored frames
        :rtype: [Frame]
        """

        # Parse every frame with the duct tape
        for frame in self._frames:
            duct_tape(frame)

        # Create the tracker from the frames which will create conversations
        # and at the same time filter the ignored frames
        tracker = CoAPTracker(self._frames)
        self.__conversations = tracker.conversations

        # Get the conversations by pair
        self.__conversations_by_pair = group_conversations_by_pair(
            self.__conversations
        )

        return tracker.ignored_frames

    def run(self) -> (str, list_of(int), str, list_of(Exception)):
        """
        Run the test case

        :return: A tuple with the informations about the running which are
                 - The verdict as a string
                 - The list of the review frames
                 - A string for extra informations
                 - A list of Exceptions that could have occured during the run
        :rtype: (str, [int], str, [Exception])
        """
        raise NotImplementedError

    def next(self, optional=False):
        try:
            f = next(self.__iter)
            self.log(f)
            self.frame = f
            return f
        except StopIteration:
            if not optional:
                self.__iter = None
                self.log("<Frame  ?>")
                self.setverdict("inconc", "premature end of conversation")
        except TypeError:
            raise self.Stop()

    def chain(self, optional=False):
        # ensure we're at the end of the current conversation
        try:
            self.log(next(self.__iter))
            self.setverdict("inconc", "unexpected frame")
            raise self.Stop()
        except StopIteration:
            pass

        last_frame = self.__current_conversation[-1]

        try:
            # next conversation
            c = self.__current_conversation.next
        except AttributeError:
            if optional:
                return False
            else:
                self.log("<Frame  ?>")
                self.setverdict("inconc", "expected another CoAP conversation")
                raise self.Stop()

        # Chain to the next conversation
        self.__current_conversation = c
        self.__iter = iter(self.__current_conversation)

        self.log("Chaining to conversation %d %s" % (c.id, c.tag))
        self.next()
        if self.frame.ts < last_frame.ts:
            self.setverdict(
                "inconc",
                "concurrency issue: frame %d was received earlier than frame %d"
                %
                (self.frame.id, last_frame.id)
            )
            raise self.Stop()

        return True

    # NOTE: Seems to be never used
    @contextmanager
    def nolog(self):
        text = self.text
        self.text = ""
        try:
            yield
        finally:
            self.text = text

    def next_skip_ack(self, optional=False):
        """Call self_next(), but skips possibly interleaved ACKs"""
        self.next(optional)
        while all((
            self.frame is not None,
            self.frame[CoAP] in CoAP(type="ack", code=0)
        )):
            self.next(optional)

        return self.frame

    def match_coap(self, sender, template, verdict="inconc"):
        assert sender in (None, "client", "server")

        if not self.__iter:
            # end of conversation
            self.setverdict(verdict, "expected %s from the %s" % (template, sender))
            self.failed_frames.add(self.frame.id)
            self.log('ENCONTRE FFAILED FRAME! : ' + self.frame.id)
            return False

        # check the sender
        src = self.frame.src[0]
        if sender == "client":
            if src != self.conversation.client:
                if verdict is not None:
                    self.setverdict(verdict, "expected %s from the client" % template)
                self.failed_frames.add(self.frame.id)
                self.log('ENCONTRE FFAILED FRAME! : ' + self.frame.id)
                return False
        elif sender == "server":
            if src != self.conversation.server:
                if verdict is not None:
                    self.setverdict(verdict, "expected %s from the server" % template)
                self.failed_frames.add(self.frame.id)
                self.log('ENCONTRE FFAILED FRAME! : ' + self.frame.id)
                return False
        else:
            assert sender is None

        # check the template
        if template:
            diff_list = DifferenceList(self.frame[CoAP])
            if template.match(self.frame[CoAP], diff_list):
                # pass
                if verdict is not None:
                    self.setverdict("pass", "match: %s" % template)

            else:
                if verdict is not None:
                    def callback(path, mismatch, describe):
                        self.log("             %s: %s\n" % (".".join(path), type(mismatch).__name__))
                        self.log("                 got:        %s\n" % mismatch.describe_value(describe))
                        self.log("                 expected: %s\n" % mismatch.describe_expected(describe))

                    self.setverdict(verdict, "mismatch: %s" % template)
                    diff_list.describe(callback)
                self.failed_frames.add(self.frame.id)
                return False

        return True

    def uri(self, uri, *other_opts):
        """filter for disabling a template if URI-Filter is disabled

        *other_opts elemements may be either:
            CoAPOption datas    -> will be fed into a Opt() together with the Uri options
            CoAPOptionList datas -> will be combined with the Opt() within a All() template
        """
        opt = []
        opt_list = []
        for o in other_opts:
            if issubclass(o.get_type(), CoAPOption):
                opt.append(o)
            elif issubclass(o.get_type(), CoAPOptionList):
                opt_list.append(o)
            else:
                raise ValueError

        if self.urifilter:
            u = urllib.parse.urlparse(uri)
            if u.path:
                assert not any(isinstance(v, CoAPOptionUriPath) for v in other_opts)
                for elem in u.path.split("/"):
                    if elem:
                        opt.append(CoAPOptionUriPath(elem))
            if u.query:
                assert not any(isinstance(v, CoAPOptionUriQuery) for v in other_opts)
                for elem in u.query.split("&"):
                    if elem:
                        opt.append(CoAPOptionUriQuery(elem))

        if opt:
            opt_list.append(Opt(*opt))

        if not opt_list:
            return None
        elif len(opt_list) == 1:
            return opt_list[0]
        else:
            return All(*opt_list)

    def get_max_age(self):
        try:
            return self.frame[CoAP]["opt"][CoAPOptionMaxAge]["val"]
        except KeyError:
            # option not present
            return 60

    def match_link_format(self, filter=None, value=None,
                          path=(CoAPOptionUriPath(".well-known"), CoAPOptionUriPath("core"))):

        if filter is None:
            opt = All(Opt(*path), NoOpt(CoAPOptionUriQuery()))
        else:
            opt = Opt(CoAPOptionUriQuery(), *path)

            if self.frame[CoAP] in CoAP(code="get", opt=opt):

                q = self.frame[CoAP]["opt"][CoAPOptionUriQuery]["val"]
                i = q.find("=")
                if i < 0:
                    self.setverdict("fail", "malformed Uri-Query option: %r" % q)
                    return

                n, v = q[:i], q[i + 1:]

                verdict = "pass"
                msg = "link-format request with filter on %s" % filter

                # filter by query name
                if n not in store_data(filter):
                    verdict = "inconc"

                if value is not None:
                    # filter by query value
                    msg += " matching %s" % value
                    if v not in store_data(value):
                        verdict = "inconc"

                self.setverdict(verdict, msg)

                self.link_filter_name, self.link_filter = n, v

                opt = Opt(CoAPOptionUriQuery(q), *path)

        szx = None
        pl = None
        blocks = {}
        while True:
            if not self.match_coap("client", CoAP(code="get", opt=opt)):
                raise self.Stop()
            self.next_skip_ack()

            if not self.match_coap("server", CoAP(code=2.05, opt=Opt(CoAPOptionContentFormat(40)))):
                raise self.Stop()

            try:
                bl2 = self.frame[CoAP]["opt"][CoAPOptionBlock2]
            except KeyError:
                # single block
                pl = self.frame[CoAP]["pl"]
                break
            else:
                # multiple blocks
                if szx is None:
                    # first block
                    szx = bl2["szx"]
                elif bl2["szx"] != szx:
                    # block size was modified
                    if bl2["szx"] > szx:
                        self.setverdict("inconc", "block size seems to be increasing")
                        raise self.Stop()

                    # block size was reduced
                    # -> rehash
                    size = 2 ** (bl2["szx"] + 4)
                    new_blocks = {}
                    mult = 2 ** (szx - bl2["szx"])
                    for num, b in blocks.items():
                        new_num = num * mult
                        for i in range(mult):
                            new_blocks[new_num + i] = b[i * size:(i + 1) * size]

                    szx = bl2["szx"]
                    blocks = new_blocks

                blocks[bl2["num"]] = self.frame[CoAP]["pl"]

                if not bl2["m"]:
                    # final block
                    break

            self.next_skip_ack()

        self.next_skip_ack(optional=True)

        if pl is None:
            pl = []
            bad = False
            for i in range(0, bl2["num"] + 1):
                b = blocks.get(i)
                if b is None:
                    bad = True
                    self.setverdict("inconc", "block #%d is missing" % i)
                else:
                    pl.append(b)
            if bad:
                raise self.Stop()
            pl = b"".join(pl)
        try:
            self.link = Link(pl)
        except Link.FormatError as e:
            self.setverdict("fail", "link-format payload is not well-formatted (%s: %s)" % (type(e).__name__, e))
            raise self.Stop()

        self.raw_link = pl

    def link_values(self):
        self.log("<Processing link-format payload>")
        entries = set()
        PAR_WIDTH = 16
        for lv in self.link:
            pars = ["%s=%r" % v for v in lv]
            offset = 0
            for i in range(len(pars)):
                p = pars[i]
                overflow = len(p) - PAR_WIDTH
                if overflow > -offset:
                    offset += overflow
                else:
                    pars[i] = p + " " * (-overflow - offset)
                    offset = 0

            self.log("           %-20r %s" % (lv.uri, "  ".join(pars)))
            entry = lv.uri, lv.get("anchor"), lv.get("rel")
            if entry in entries:
                self.log("WARNING: duplicate link ")
            entries.add(entry)
            yield lv


class Link (list):
    __re_uri        = re.compile (r"<([^>]*)>")
    __re_par_name = re.compile (r";([0-9A-Za-z!#$%&+^_`{}~-]+)(=?)")
    __re_ptoken     = re.compile (r"[]!#$%&'()*+./:<=>?@[^_`{|}~0-9A-Za-z-]+")

    class FormatError (Exception):
        pass

    def __init__ (self, pl):    # may throw exceptions in case of bad format

        def error (msg, in_string = None):
            if in_string:
                raise self.FormatError ("%s in %r" % (msg, in_string))
            else:
                raise self.FormatError ("%s at %r..." % (msg, s[:40]))

        mo = None
        try:
            s  = str (pl, "utf-8")
        except UnicodeDecodeError as e:
            error (str(e), pl)

        def have (string):
            return s and s.startswith (string)

        def consume (pattern, subject):
            nonlocal s, mo
            if isinstance (pattern, str):
                # str
                if s.startswith (pattern):
                    s = s[len(pattern):]
                    return
            else:
                # regex
                mo = re.match (pattern, s)
                if mo:
                    s = s[mo.end(0):]
                    return
            error ("malformed %s" % subject)

        def percent_unquote (string):
            try:
                return urllib.parse.unquote (string, errors="strict")
            except UnicodeDecodeError as e:
                error (str(e), string)

        if s:
            while True:
                # link-value
                consume (self.__re_uri, "uri")
                uri = percent_unquote (mo.group (1))

                link_value = self.LinkValue (uri)

                while have (";"):
                    # link-param
                    consume (self.__re_par_name, "parmname")
                    name = mo.group (1)

                    if not mo.group (2):
                        value = None

                    elif (have ('"')):
                        # quoted-string
                        #  -> read and unquote it
                        value = []
                        esc = False
                        for i in range (1, len (s)):
                            c = s[i]
                            if not esc:
                                if c == '\\':
                                    esc = True
                                elif c == '"':
                                    # end of string
                                    break
                                else:
                                    # TODO: normalise LWS
                                    value.append (c)
                            else:
                                esc = False

                                if c == '"' or c == '\\':
                                    # quoted char
                                    value.append (c)
                                else:
                                    # was an unquoted \
                                    value.append ('\\' + c)
                        else:
                            error ("attribute value for %r is an unterminated quoted-string" % name)

                        value = "".join (value)
                        if not value:
                            error ("attribute value for %r is empty" % name)
                        s = s[i+1:]
                    else:
                        # ptoken
                        consume (self.__re_ptoken, "ptoken")
                        value = percent_unquote (mo.group (0))

                    link_value.append ((name, value))

                self.append (link_value)

                if not s:
                    break

                # next link-value
                consume (",", "delimiter, expected ','")

    class LinkValue (list):
        def __init__ (self, uri):
            self.uri = uri

        def get (self, par_name, testcase = None):
            result = None
            for name, value in self:
                if name == par_name:
                    if result is None:
                        result = value
                    else:
                        msg = "link-value contains multiple %r parameters" % par_name
                        if testcase:
                            testcase.setverdict ("fail", msg)
                        else:
                            raise Exception (msg)
            return result


class CoAPTracker:
    """
    Tracker class to create conversations from frame list
    """

    class FlowState:
        """
        Tool to link a frame to others in order to generate the final conv

        The main responsability of this tool class is to manage many
        conversations that can be interleaved. It will map a request
        with its corresponding response.
        """

        @typecheck
        def __init__(self, tracker: this_class):
            """
            Initialize the flow state with a tracker object, its main concern
            is to provide an easy way to create conversations and maintains a
            list of ignored frames

            :param tracker: The CoAPTracker object which will have its
                            conversation populated
            :type tracker: CoAPTracker
            """
            self.__tracker = tracker

            # msgid -> (conversation, timeout)
            self.by_mid = {}

            # token -> conversation
            self.by_request_token = {}

            # token -> conversation     (Block1)
            # uri   -> conversation     (Block2)
            self.by_bl = {}

            # uri -> conversation
            self.obs_by_uri = {}

            # token -> conversation
            self.obs_by_token = {}

        @typecheck
        def append(self, frame: Frame):
            """
            Append a new frame to the current flow state

            :param frame: The frame to append
            :type frame: Frame
            """

            # Get the token and options
            token = frame[CoAP]["tok"]
            opt = frame[CoAP]["opt"]

            # A temporary value to store the current conversation
            conv = None

            # REQUEST or PING frame
            if any((
                frame[CoAP].is_request(),
                all((
                    frame[CoAP]["code"] == 0,
                    frame[CoAP]["type"] == 0
                ))
            )):

                # Get its uri
                uri = frame[CoAP].get_uri()

                # Handle block options
                try:

                    # Get block option
                    block_option = opt[CoAPOptionBlock]

                    # It is a request w/ a block
                    if isinstance(block_option, CoAPOptionBlock1):

                        # Get the conversation from current dictionnary
                        conv = self.by_bl.get(token)

                        # Final block of an existing conversation
                        # Clear the by block dict associated to this token
                        if conv and not block_option['m']:
                            del self.by_bl[token]

                        # New block1 conversation w/ more blocks
                        # Create the by block dict associated to this token
                        elif block_option['m']:
                            conv = self.__tracker.new_conversation(frame)
                            self.by_bl[token] = conv

                    # Block2 option (a block option is Block1 or Block2 type)
                    else:

                        # Get the corresponding conversations from the uri
                        conv = self.by_bl.get(uri)

                        # If it exists, clear the conv got from the uri mapping
                        # And map it to its token value
                        if conv:
                            del self.by_bl[uri]
                            self.by_request_token[token] = conv

                # Not a block conversation
                except KeyError:

                    # If a conversation is found
                    if conv:

                        # Discard the state in by_bl
                        if token in self.by_bl:
                            del self.by_bl[token]
                        if uri in self.by_bl:
                            del self.by_bl[uri]

                        # And start a new conversation
                        conv = None

                # If new conversation
                if not conv:

                    # Handle observe option
                    conv = self.obs_by_uri.get(uri)

                    try:
                        obs = opt[CoAPOptionObserve]

                        # This is a new conversation
                        if not conv or not conv.__obs_active:
                            conv = self.__tracker.new_conversation(frame)
                            conv.__obs_active = True
                            self.obs_by_uri[uri] = conv

                        # Remember the token
                        self.obs_by_token[token] = conv

                    # Not with observe option
                    except KeyError:

                        # This observation is no longer active
                        if conv and conv.__obs_active:
                            conv.__obs_active = False

                        # Unrelated new conversation
                        else:
                            conv = self.__tracker.new_conversation(frame)

                        # Map it from its token
                        self.by_request_token[token] = conv

                # Check that at the end of a request managment, we have a
                # conversation and an uri. The goal is to match a request
                # with its corresponding response
                assert conv
                conv.__uri = uri

            # Response frame
            elif frame[CoAP].is_response():

                # Match by token
                try:

                    # If response of a simple request
                    try:
                        conv = self.by_request_token.pop(token)

                    # If observable response
                    except KeyError:
                        conv = self.obs_by_token[token]

                    # Track block2 transfers
                    bl2 = opt[CoAPOptionBlock2]

                    if bl2['M']:
                        self.by_bl[conv.__uri] = conv
                except KeyError:
                    pass

            # Matching by message id for RST & ACK
            mid = frame[CoAP]['mid']
            typ = frame[CoAP]['type']

            # CON frame w/ known conversation
            if typ == 0 and conv:

                # Record the mid
                self.by_mid[mid] = conv, frame.ts + MAX_TIMEOUT

            # ACK/RST frame w/o known conversation
            elif typ > 1 and not conv:

                # Try matching by message-id
                try:
                    conv, timeout = self.by_mid[mid]

                    # If timeout passed, delete the conv because inconsistant
                    if frame.ts > timeout:
                        del self.by_mid[mid]
                        conv = None
                except KeyError:
                    pass

            # RST frame
            if typ == 3:

                # Observable not anymore active
                if conv:
                    conv.__obs_active = False

                # If another conv was registered, not anymore active too
                conv2 = self.obs_by_token.get(token)
                if conv2:
                    conv2.__obs_active = False

            # If we found a corresponding conv for this response
            if conv:
                conv.append(frame)

            # If none, add it to the ignored ones
            else:
                self.__tracker.ignored_frames.append(frame)

    @typecheck
    def __init__(self, frames: list_of(Frame) = []):
        """
        Initialize the CoAP Tracker with a frame list

        :param frames: List of frames
        :type frames: [Frame]
        """
        self.reset()
        self.append(frames)

    def reset(self):
        """
        Reset the tracker, clear all its list and dict
        """
        self.conversations = []
        self.ignored_frames = []
        self.__states = {}

    @staticmethod
    @typecheck
    def flow_tag(frame: Frame) -> str:
        """
        Generate a tag for a flow, consists into displaying the two adresses

        :param frame: The frame from which we will generate the tag
        :type frame: Frame

        :return: A tag of the flow consisting into the adresses of the two
                 communicating entities
        :rtype: str
        """
        assert CoAP in frame

        src, dst = frame.src, frame.dst

        return str((src, dst)) if src < dst else str((dst, src))

    @typecheck
    def new_conversation(self, frame: Frame) -> CoAPConversation:
        """
        Generate a new conversation

        :param frame: The first frame of the new conversation
        :type frame: Frame

        :return: A new conversation containing the entered frame
        :rtype: CoAPConversation
        """
        t = CoAPConversation(frame)
        self.conversations.append(t)
        t.id = len(self.conversations)
        return t

    @typecheck
    def append(self, frames: list_of(Frame)):
        """
        Put the frames into the tracker lists
        """
        for f in frames:

            # Not a coap frame
            if CoAP not in f:
                self.ignored_frames.append(f)
                continue

            # Get the flow tag of this frame "(src, dst)" or "(dst, src)"
            tag = self.flow_tag(f)

            # Try to get the corresponding flowstate
            try:
                state = self.__states[tag]

            # If none found, create it
            except KeyError:
                state = self.FlowState(self)
                self.__states[tag] = state

            # In the end, add it to the flow state
            state.append(f)


@typecheck
def group_conversations_by_pair(
    conversations: list_of(CoAPConversation)
) -> dict_of((Value, Value), list_of(CoAPConversation)):
    """
    Group a list of conversations by pair

    :param conversations: The list of conversations to regroup by pair
    :type conversations: [CoAPConversation]

    :return: A dict mapping of the client/server @ pair and the list ofconv
    :rtype: {(Value, Value): [CoAPConversation]}
    """
    d = {}
    for t in conversations:
        pair = t.client, t.server
        try:
            d[pair].append(t)

            # Chain successive conversations together
            d[pair][-2].next = t
        except KeyError:
            d[pair] = [t]
    return d


class Resolver:
    __cache = {}

    def __new__(cls, ip_addr):
        try:
            return cls.__cache[ip_addr]
        except KeyError:
            pass

        try:
            name = socket.gethostbyaddr(str(ip_addr))[0]
        except socket.herror:
            name = None

        cls.__cache[ip_addr] = name

        return name

    @classmethod
    def format(cls, ip_addr):
        name = cls(ip_addr)

        if name:
            return "%s (%s)" % (name, ip_addr)
        else:
            return ip_addr


def analyze_fix():

    # Parse the conversations grouped by pair
    # pair => A tuple (client, server)
    # conversations => A list of corresponding conversations put by
    #                  pair and in temporal order
    for pair, conversations in conversations_by_pair.items():

        # The results also by pair
        pair_results = []

        # For every test cases found (most of the time, there will be
        # only one)
        for tc_type in test_cases:

            # Results for each tc
            tc_results = []

            # We run the testcase for each conversation, meaning that
            # one type of TC can have more than one result!
            for tr in conversations:

                # Create the CoAPTestCase object from parameters
                tc = tc_type(tr, None, True)

                # If there's a result
                if tc.verdict:
                    tc_results.append(tc)

                    # If exception, add it to the function parameter
                    if all((
                        hasattr(tc, "exception"),
                        exceptions is not None
                    )):
                        exceptions.append(tc)

            # Append the results of each test case confronted to this
            # conversation pair
            pair_results.append(tc_results)

    # Get only the results of the test case that we requested
    # You can look upper and see that we loop on ALL the test cases,
    # whereas here we only loop on the requested ones (can be many)
    for tc_type, tc_results in filter(
        lambda x: tc_id in x[0].__name__,
        zip(test_cases, pair_results)
    ):
        # (tc_type, tc_results) = filter(
        #     lambda x: tc_id == x[0].__name__,  # Take only the requested tc
        #     zip(test_cases, pair_results)  # Parse the 2 lists in parallel
        # )

        # Prepare the review frames list
        review_frames = []

        # Current verdict (inconc)
        v = 0

        # For every results
        for tc in tc_results:

            # All the failed frames for a TC, even if they are from
            # different conversations!
            review_frames = tc.failed_frames

            # Get the new verdict and update current one if the new has
            # higher priority
            new_v = self.verdicts.index(tc.verdict)
            if new_v > v:
                v = new_v

        # Get the text value of the verdict
        v_txt = self.verdicts[v]
        if v_txt is None:
            v_txt = "none"

        # Compute the extra informations
        extra_info = tc.text if verbose else ''

    pass


if __name__ == "__main__":
    filename = '/'.join((
        'tests',
        'test_dumps',
        '_'.join((
            'TD',
            'COAP',
            'CORE',
            '07',
            'FAIL',
            'No',
            'CoAPOptionContentFormat',
            'plus',
            'random',
            'UDP',
            'messages.pcap'
        ))
    ))
    frame_list = Frame.create_list(PcapReader(filename))

    for frame in frame_list:
        duct_tape(frame)

    tracker = CoAPTracker(frame_list)
    conversations = tracker.conversations
    ignored = tracker.ignored_frames
    print('#####')
    print('##### Conversations')
    print(conversations)
    print('#####')
    print('##### Ignored')
    print(ignored)
    print('#####')
    print('##### Conversations by pair')
    conversations_by_pair = group_conversations_by_pair(conversations)
    print(conversations_by_pair)
    print('#####')
