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

import traceback, urllib.parse, re


from ttproto.core.lib.inet.coap import *
from ttproto.core.templates import All
from ttproto.core.data import store_data, DifferenceList

from contextlib import contextmanager

from .proto_templates import Opt, NoOpt, Not

RESPONSE_TIMEOUT = 2
RESPONSE_RANDOM_FACTOR = 1.5
MAX_RETRANSMIT = 4

MAX_TIMEOUT = 10 + round ((RESPONSE_TIMEOUT * RESPONSE_RANDOM_FACTOR) * 2**MAX_RETRANSMIT)


class CoAPConversation (list):
    def __init__ (self, request_frame):
        assert request_frame.coap
        assert request_frame.coap.is_request() or (request_frame.coap["code"]==0 and request_frame.coap["type"]==0)

        self.tag = self.gen_tag (request_frame)
#       self.append (request_frame)
#       self.update_timeout (request_frame)

        self.client = request_frame.src[0]
        self.server = request_frame.dst[0]

    def update_timeout (self, request_frame):
        self.timeout = request_frame.ts + MAX_TIMEOUT

    def __hash__ (self):
        return id (self)

    def __bool__ (self):
        return True

    @staticmethod
    def gen_tag (frame):
        assert frame.coap

        if frame.coap.is_request():
            return frame.src, frame.dst
        else:
            return frame.dst, frame.src


class CoAPTestcase(object):
    obsolete = False
    reverse_proxy = False

    __verdicts = None, "pass", "inconclusive", "fail", "error"

    class Stop (Exception):
        pass

    def __init__ (self, conversation: CoAPConversation, urifilter = False, force = False):
        self.conversation= conversation
        self.text   = ""
        self.urifilter  = urifilter
        self.force  = force
        # set to avoid repetitions
        self.failed_frames = set()
        self.review_frames_log = []
        try:
            self.verdict = None
            self.__current_conversation = self.conversation
            self.__iter = iter (self.__current_conversation)
            self.next()

            self.run()

            # ensure we're at the end of the communication
            try:
                self.log (next (self.__iter))
                self.setverdict ("inconclusive", "unexpected frame")
            except StopIteration:
                pass

        except self.Stop:
            # ignore this testcase result if the first frame gives an inconclusive verdict
            if self.verdict == "inconclusive" and self.frame == self.conversation[0] and not self.force:
                # no match
                self.verdict = None

        except Exception:
            if self.__iter:
                self.setverdict ("error", "unhandled exception")
                self.exception = traceback.format_exc()
                self.log (self.exception)

        assert self.verdict in self.__verdicts

    def next (self, optional = False):
        try:
            f =  next (self.__iter)
            self.log (f)
            self.frame = f
            return f
        except StopIteration:
            if not optional:
                self.__iter = None
                self.log ("<Frame  ?>")
                self.setverdict ("inconclusive", "premature end of conversation")
        except TypeError:
            raise self.Stop()

    def chain (self, optional = False):
        # ensure we're at the end of the current conversation
        try:
            self.log (next (self.__iter))
            self.setverdict ("inconclusive", "unexpected frame")
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
                self.log ("<Frame  ?>")
                self.setverdict ("inconclusive", "expected another CoAP conversation")
                raise self.Stop()


        # Chain to the next conversation
        self.__current_conversation = c
        self.__iter = iter (self.__current_conversation)

        self.log ("Chaining to conversation %d %s" % (c.id, c.tag))
        self.next()
        if self.frame.ts < last_frame.ts:
            self.setverdict ("inconclusive", "concurrency issue: frame %d was received earlier than frame %d" % (self.frame.id, last_frame.id))
            raise self.Stop()

        return True

    def setverdict (self, v, text = ""):
        if self.verdict is None and v == "inconclusive" and not self.force:
            raise self.Stop()

        if self.__verdicts.index (v) > self.__verdicts.index (self.verdict):
            self.verdict = v

        self.log ("  [%s] %s" % (format (v, "^6s"), text))

    def log(self, text):
        text = str(text)
        self.text += text if text.endswith("\n") else (text + "\n")
        self.review_frames_log.append(text)


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
        while (self.frame is not None) and (self.frame.coap in CoAP(type="ack", code=0)):
            self.next(optional)

        return self.frame

    def match_coap(self, sender, template, verdict="inconclusive"):
        assert sender in (None, "client", "server")

        if not self.__iter:
            # end of conversation
            self.setverdict(verdict, "expected %s from the %s" % (template, sender))
            self.failed_frames.add(self.frame.id)
            return False

        # check the sender
        src = self.frame.src[0]
        if sender == "client":
            if src != self.conversation.client:
                if verdict is not None:
                    self.setverdict(verdict, "expected %s from the client" % template)
                self.failed_frames.add(self.frame.id)
                return False
        elif sender == "server":
            if src != self.conversation.server:
                if verdict is not None:
                    self.setverdict(verdict, "expected %s from the server" % template)
                self.failed_frames.add(self.frame.id)
                return False
        else:
            assert sender is None

        # check the template
        if template:
            diff_list = DifferenceList(self.frame.coap)
            if template.match(self.frame.coap, diff_list):
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

    def run(self):
        raise NotImplementedError()

    @classmethod
    def get_objective(self):
        if self.__doc__:
            ok = False
            for line in self.__doc__.splitlines():
                if ok:
                    return line
                if line == "Objective:":
                    ok = True
        return ""

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
            return self.frame.coap["opt"][CoAPOptionMaxAge]["val"]
        except KeyError:
            # option not present
            return 60

    def match_link_format(self, filter=None, value=None,
                          path=(CoAPOptionUriPath(".well-known"), CoAPOptionUriPath("core"))):

        if filter is None:
            opt = All(Opt(*path), NoOpt(CoAPOptionUriQuery()))
        else:
            opt = Opt(CoAPOptionUriQuery(), *path)

            if self.frame.coap in CoAP(code="get", opt=opt):

                q = self.frame.coap["opt"][CoAPOptionUriQuery]["val"]
                i = q.find("=")
                if i < 0:
                    self.setverdict("fail", "malformed Uri-Query option: %r" % q)
                    return

                n, v = q[:i], q[i + 1:]

                verdict = "pass"
                msg = "link-format request with filter on %s" % filter

                # filter by query name
                if n not in store_data(filter):
                    verdict = "inconclusive"

                if value is not None:
                    # filter by query value
                    msg += " matching %s" % value
                    if v not in store_data(value):
                        verdict = "inconclusive"

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
                bl2 = self.frame.coap["opt"][CoAPOptionBlock2]
            except KeyError:
                # single block
                pl = self.frame.coap["pl"]
                break
            else:
                # multiple blocks
                if szx is None:
                    # first block
                    szx = bl2["szx"]
                elif bl2["szx"] != szx:
                    # block size was modified
                    if bl2["szx"] > szx:
                        self.setverdict("inconclusive", "block size seems to be increasing")
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

                blocks[bl2["num"]] = self.frame.coap["pl"]

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
                    self.setverdict("inconclusive", "block #%d is missing" % i)
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
    class FlowState:
        def __init__ (self, tracker):
            self.__tracker = tracker

            # msgid -> (conversation, timeout)
            self.by_mid = {}

            # token -> conversation
            self.by_request_token={}

            # token -> conversation     (Block1)
            # uri   -> conversation     (Block2)
            self.by_bl = {}

            # uri -> conversation
            self.obs_by_uri = {}

            # token -> conversation
            self.obs_by_token = {}

        def append (self, frame):

            # get the token
            token = frame.coap["tok"]
            #print (" token:", repr(token))
            tr  = None
            opt = frame.coap["opt"]

            if frame.coap.is_request() or (frame.coap["code"]==0 and frame.coap["type"]==0):
                # frame is a request or a ping
                uri = frame.coap.get_uri()
                #print (" uri:", uri)

                # handle block options
                try:
                    bl = opt[CoAPOptionBlock]
                    #print (" bl:", bl)

                    # it is a request w/ a block
                    if isinstance (bl, CoAPOptionBlock1):
                        tr = self.by_bl.get (token)
                        #print (" tr:", tr)

                        # block1 option
                        if tr:
                            if not bl["m"]:
                                # final block of an existing conversation
                                del self.by_bl[token]

                        elif bl["m"]:
                            # new block1 conversation w/ more blocks
                            tr = self.__tracker.new_conversation (frame)
                            self.by_bl[token] = tr
                    else:
                        # block2 option
                        #print (" block2")

                        tr = self.by_bl.get (uri)
                        #print (" tr:", tr)

                        if tr:
                            #print (" delete from by_bl")
                            del self.by_bl[uri]
                            self.by_request_token[token] = tr

                except KeyError:
                    # not a block conversation
                    if tr:
                        # -> discard the state in by_bl and start a new conversation
                        if token in self.by_bl:
                            del self.by_bl[token]
                        if uri in self.by_bl:
                            del self.by_bl[uri]

                        tr = None

                if not tr:
                    # handle observe option
                    tr = self.obs_by_uri.get (uri)

                    try:
                        obs = opt[CoAPOptionObserve]
                        if not tr or not tr.__obs_active:
                            # this is a new conversation
                            tr = self.__tracker.new_conversation (frame)
                            tr.__obs_active = True
                            self.obs_by_uri[uri] = tr

                        # remember the token
                        self.obs_by_token[token] = tr

                    except KeyError:
                        if tr and tr.__obs_active:
                            # this observation is no longer active
                            tr.__obs_active = False
                        else:
                            # unrelated new conversation
                            tr = self.__tracker.new_conversation (frame)

                        self.by_request_token[token] = tr

                tr.__uri = uri
                assert tr

            elif frame.coap.is_response():
                # response frame

                #print (" response")
                # match by token
                try:
                    try:
                        tr = self.by_request_token.pop (token)
                    except KeyError:
                        #print (" key error 1")
                        tr = self.obs_by_token[token]
                    #print (" tr:", tr)

                    # track block2 transfers
                    bl2 = opt[CoAPOptionBlock2]
                    #print (" response bl2")
                    #print (" bl2[M]", bl2["M"])

                    if bl2["M"]:
                        self.by_bl[tr.__uri] = tr
                except KeyError:
                    #print (" key error 2")
                    pass

            #print (" by_bl[token]:", self.by_bl.get(token))
            #if tr:
                #print (" tr.__uri:", tr.__uri)
                #print (" by_bl[tr.__uri]:", self.by_bl.get(tr.__uri))
            # matching by message id for RST & ACK
            #
            mid = frame.coap['mid']
            typ = frame.coap['type']
            if typ==0 and tr:
                # CON frame w/ known conversation

                # record the mid
                self.by_mid[mid] = tr, frame.ts + MAX_TIMEOUT

            elif typ>1 and not tr:
                # ACK/RST frame w/o known conversation

                # -> try matching by message-id
                try:
                    tr, timeout = self.by_mid[mid]
                    if frame.ts > timeout:
                        del self.by_mid[mid]
                        tr = None
                except KeyError:
                    pass

            if typ == 3: # RST
                if tr:
                    tr.__obs_active = False

                tr2 = self.obs_by_token.get (token)
                if tr2:
                    tr2.__obs_active = False

            if tr:
                tr.append (frame)
            else:
                self.__tracker.ignored_frames.append (frame)


    def __init__ (self, frames = ()):
        self.reset()
        self.append (frames)

    def reset (self):
        self.conversations = []
        self.ignored_frames = []
        self.__states = {}

    @staticmethod
    def flow_tag (frame):
        assert frame.coap

        src, dst = frame.src, frame.dst

        return str ((src, dst)) if src < dst else str ((dst, src))

    def new_conversation (self, frame):
        t = CoAPConversation (frame)
        self.conversations.append (t)
        t.id = len (self.conversations)
        return t


    def append (self, frames):
        for f in frames:
            #print (f)
            if not f.coap:
                # not a coap frame
                self.ignored_frames.append (f)
                continue

            tag = self.flow_tag (f)
            #print (" tag:", tag)

            try:
                state = self.__states [tag]
            except KeyError:
                state = self.FlowState (self)
                self.__states[tag] = state
            #print (" state:", state)

            state.append (f)

#       for s in self.__states:
#           print (s)


def extract_coap_conversations (frames):
    conversations = []
    ignored_frames = []

    id_t = 1

    # tag -> conversation
    actives = {}


    # TODO: garbage-collect timeouts every N frames
    for f in frames:

        if not f.coap:
            # we care only about coap packets
            ignored_frames.append (f)
            continue

        # We have a CoAP frame
        tag = CoAPConversation.gen_tag (f)
        t = actives.get (tag)
        if t:
            # we have an existing conversation w/ this tag
            if f.ts > t.timeout:
                # this conversation has expired
                del actives[tag]
            else:
                # append this frame to the existing conversation
                t.append (f)
                if f.coap.is_request():
                    t.update_timeout(f)
                continue

        # we have no valid conversation for that tag

        if f.coap.is_response():
            ignored_frames.append (f)
            continue


        # We have a CoAP request
        # -> begin a new conversation
        t = CoAPConversation (f)
        t.id = id_t
        id_t += 1

        assert t.tag == tag

        conversations.append (t)
        actives[tag] = t

    return conversations, ignored_frames


def group_conversations_by_pair (conversations):
    d = {}
    for t in conversations:
        pair = t.client, t.server
        try:
            d[pair].append (t)

            # chain successive conversations together
            d[pair][-2].next = t
        except KeyError:
            d[pair] = [t]
    return d


class TD_COAP_TEST_BAD_CHAINING (CoAPTestcase):

    def run (self):
        self.match_coap ("client", CoAP (code = "get", opt=self.uri("/test")))
        self.next()
        self.match_coap ("server", CoAP (code = 2.05, pl = Not(b'')))
        self.chain()
        self.match_coap ("client", CoAP (code = "get", opt=self.uri("/hello")))
        self.next()
        self.match_coap ("server", CoAP (code = 2.05, pl = Not(b'')))


class TD_COAP_TEST_GOOD_CHAINING (CoAPTestcase):

    def run (self):
        self.match_coap ("client", CoAP (code = "get", opt=self.uri("/seg1")))
        self.next()
        self.match_coap ("server", CoAP (code = 2.05, pl = Not(b'')))
        self.chain()
        self.match_coap ("client", CoAP (code = "get", opt=self.uri("/seg1/seg2")))
        self.next()
        self.match_coap ("server", CoAP (code = 2.05, pl = Not(b'')))
        self.chain()
        self.match_coap ("client", CoAP (code = "get", opt=self.uri("/seg1/seg2/seg3")))
        self.next()
        self.match_coap ("server", CoAP (code = 2.05, pl = Not(b'')))



