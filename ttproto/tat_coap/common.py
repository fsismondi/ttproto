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

import re
import socket
import sys
import time

from .data import *
from ttproto.core.analyzer import TestCase, Verdict, is_verdict, is_traceback
from ttproto.core.dissector import Frame
from ttproto.core.templates import All, Not, Any, Length
from ttproto.core.typecheck import *
from ttproto.core.lib.all import *
from urllib import parse


# CoAP constants
RESPONSE_TIMEOUT = 2
RESPONSE_RANDOM_FACTOR = 1.5
MAX_RETRANSMIT = 4
MAX_TIMEOUT = 10 + round(
        (RESPONSE_TIMEOUT * RESPONSE_RANDOM_FACTOR) * 2**MAX_RETRANSMIT
    )


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


class CoAPTestCase(TestCase):
    """
    The test case extension representing a CoAP test case
    """

    # Some default parameters
    reverse_proxy = False
    urifilter = False

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

        # Initialize its verdict instance and its list of frame
        self.__verdict = Verdict()
        self.__frames = frame_list

        # Prepare the parameters
        self.__conversations = []
        self.__text = ''
        self.__failed_frames = []
        self.__exceptions = []

    @typecheck
    def match(
        self,
        sender: optional(str),
        template: Value,
        verdict: optional(is_verdict) = 'inconc',
        msg: str = ''
    ) -> bool:
        """
        Abstract function to match the current frame value with a template

        :param sender: The sender of the packet
        :param template: The template to confront with current frame value
        :param verdict: The verdict to put if it matches
        :param msg: The message to associated with the verdict
        :type sender: str
        :type template: Value
        :type verdict: str
        :type msg: str

        :return: True if the current frame value matched the given template
        :rtype: bool
        """

        # Specific to CoAP
        assert sender in (None, 'client', 'server')

        # If we're expecting a frame but it's the end of conversation
        if not self.__iter:
            self.set_verdict(
                verdict,
                'expected %s from the %s' % (template, sender)
            )

            # Add this frame's id to the failed frames
            self.__failed_frames.append(self.__frame.get_id())
            self.log('ENCOUNTER FAILED FRAME! : ' + str(self.__frame.get_id()))

            # Frame value didn't match the template (error in fact)
            return False

        # Check the sender
        src = self.__frame.src[0]

        # Check that the src is the same that the conversation's client/server
        if src != getattr(self.__current_conversation, sender):

            # If a verdict is given, put it
            if verdict is not None:
                self.set_verdict(
                    verdict,
                    'Expected %s from the %s' % (template, sender)
                )

            # Add this frame's id to the failed frames
            self.__failed_frames.append(self.__frame.get_id())
            self.log('ENCOUNTER FAILED FRAME! : ' + self.__frame.get_id())

            # Frame value didn't match the template (error in fact)
            return False

        # Check the template
        if template:
            diff_list = DifferenceList(self.__frame[CoAP])

            # If it matches
            if template.match(self.__frame[CoAP], diff_list):
                if verdict is not None:
                    self.set_verdict('pass', 'Match: %s' % template)

            # If it didn't match
            else:
                if verdict is not None:
                    def callback(path, mismatch, describe):
                        self.log(
                            "             %s: %s\n"
                            %
                            (
                                ".".join(path),
                                type(mismatch).__name__
                            )
                        )
                        self.log(
                            "                 got:        %s\n"
                            %
                            mismatch.describe_value(describe)
                        )
                        self.log(
                            "                 expected: %s\n"
                            %
                            mismatch.describe_expected(describe)
                        )

                    # Put the verdict
                    self.set_verdict(verdict, 'Mismatch: %s' % template)
                    diff_list.describe(callback)

                # Add this frame's id to the failed frames
                self.__failed_frames.append(self.__frame.get_id())

                # Frame value didn't match the template
                return False

        # If it matched, return True
        return True

    @typecheck
    def next(self, optional: bool = False):
        """
        Switch to the next frame

        :param optional: If we have to get a next frame or not
        :type optional: bool
        """
        try:
            f = next(self.__iter)
            self.log(f)
            self.__frame = f
            return f
        except StopIteration:
            if not optional:
                self.__iter = None
                self.log('<Frame  ?>')
                self.set_verdict('inconc', 'premature end of conversation')
        except TypeError:
            raise self.Stop()

    @typecheck
    def next_skip_ack(self, optional: bool = False):
        """
        Call self.next() but skips possibly interleaved ACKs

        :param optional: If we have to get a next frame or not
        :type optional: bool
        """

        # Goes to next frame
        self.next(optional)

        # While there is one and that it's an ack, pass it
        while all((
            self.__frame is not None,
            self.__frame[CoAP] in CoAP(type='ack', code=0)
        )):
            self.next(optional)

        # Return the next non ack frame
        return self.__frame

    @typecheck
    def log(self, msg):
        """
        Log a message

        :param msg: The message to log, can be of any type
        :type msg: object
        """
        text = str(msg)
        self.__text += text if text.endswith("\n") else (text + "\n")

    @classmethod
    @typecheck
    def get_test_purpose(self) -> str:
        """
        Get the purpose of this test case

        :return: The purpose of this test case
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
        return ''

    @typecheck
    def set_verdict(self, verdict: is_verdict, msg: str = ''):
        """
        Update the current verdict of the current test case

        :param verdict: The new verdict
        :param msg: The message to associate with the verdict
        :type verdict: str
        :type msg: str
        """
        # Update the verdict
        self.__verdict.update(verdict, msg)

        # TODO: Check that the log function will be used like this
        self.log("  [%s] %s" % (format(verdict, "^6s"), msg))

    @typecheck
    def pre_process(self) -> list_of((str, list_of(Frame))):
        """
        Function for each TC to preprocess its list of frames

        :return: The list of ignored frames associated to the ignoring reason
        :rtype: (str, [Frame])
        """

        # Get malformed frames
        malformed = [frame for frame in self.__frames if frame.is_malformed()]

        # Remove them from current frames
        self.__frames = [f for f in self.__frames if f not in malformed]

        # Parse every frame with the duct tape
        # FIXME: This will be removed when we have a cleaner way to put the
        #        main informations of every frame layer
        for frame in self.__frames:
            duct_tape(frame)

        # Create the tracker from the frames which will create conversations
        # and at the same time filter the ignored frames
        tracker = CoAPTracker(self.__frames)

        # Put the conversations by pair
        self.__conversations = group_conversations_by_pair(
            tracker.conversations
        )

        # Create the returned list of ignored frames and their reason
        ignored = []
        ignored.append(('malformed', malformed))
        ignored.append(('non_coap', tracker.ignored_frames))

        # Return the ignored frames
        return ignored

    @typecheck
    def run_test_case(self) -> (
        str,
        list_of(int),
        str,
        list_of((type, Exception, is_traceback))
    ):
        """
        Run the test case

        :return: A tuple with the informations about the test results which are
                 - The verdict as a string
                 - The list of the result important frames
                 - A string for extra informations
                 - A list of typles representing the exceptions that occured
        :rtype: (str, [int], str, [(type, Exception, traceback)])
        """

        # For every conversation's pair
        for pair, conversation in self.__conversations.items():

            # Get the first conversation
            # Note: We don't need to parse the conversations because the
            # chain() function will do it for us
            self.__current_conversation = conversation[0]
            self.__iter = iter(self.__current_conversation)

            # Put iterator on the first frame
            self.next()

            try:

                # Run the test case
                self.run()

                # Ensure we're at the end of the communication
                try:
                    self.log(next(self.__iter))
                    self.set_verdict('inconc', 'unexpected frame')
                except StopIteration:
                    pass

            except self.Stop:
                # Ignore this testcase result if the first frame gives an
                # inconc verdict
                if all((
                    self.__verdict.get_value() == 'inconc',
                    self.__frame == self.__current_conversation[0]
                )):
                    # No match
                    self.set_verdict('none', 'no match')

            except Exception:

                # Only if not at the end of the conversation
                if self.__iter:

                    # Get the execution informations, it's a tuple with
                    #     - The type of the exception being handled
                    #     - The exception instance
                    #     - The traceback object
                    exc_info = sys.exc_info()

                    # Add those exception informations to the list
                    self.__exceptions.append(exc_info)

                    # Put the verdict and log the exception
                    self.set_verdict('error', 'unhandled exception')
                    self.log(exc_info[1])

        # Return the results
        return (
            self.__verdict.get_value(),
            self.__failed_frames,
            self.__text,
            self.__exceptions
        )

    @typecheck
    def chain(self, optional: bool = False) -> bool:
        """
        Chain the conversations

        :param optional: True if a next conv is required, False if not
        :type optional: bool

        :raises Stop: If the conversation chaining isn't as expected

        :return: True if we managed to chain correctly, False if not
        :rtype: bool
        """

        # Ensure we're at the end of the current conversation
        try:
            self.log(next(self.__iter))
            self.set_verdict('inconc', 'unexpected frame')
            raise self.Stop()
        except StopIteration:
            pass

        # Get the last frame
        last_frame = self.__current_conversation[-1]

        # Next conversation
        try:
            next_conv = self.__current_conversation.next
        except AttributeError:
            if optional:
                return False
            else:
                self.log('<Frame  ?>')
                self.set_verdict(
                    'inconc',
                    'expected another CoAP conversation'
                )
                raise self.Stop()

        # Chain to the next conversation
        self.__current_conversation = next_conv
        self.__iter = iter(self.__current_conversation)

        # Little logging
        self.log(
            "Chaining to conversation %d %s"
            %
            (next_conv.id, next_conv.tag)
        )

        # Put the iterator on the first frame of this conv
        self.next()

        # If concurrency issue
        if self.__frame.ts < last_frame.ts:
            self.set_verdict(
                "inconc",
                "concurrency issue: frame %d was received earlier than frame %d"
                %
                (self.__frame.get_id(), last_frame.get_id())
            )
            raise self.Stop()

        # True: We managed to chain the conversations
        return True

    @typecheck
    def get_coap_layer(self) -> CoAP:
        """
        Get the coap layer of the current frame

        :return: The coap layer of the current frame
        :rtype: CoAP
        """
        return self.__frame[CoAP]

    @typecheck
    def uri(self, uri: str, *other_opts):
        """
        Filter for disabling a template if URI-Filter is disabled

        :param uri: The uri
        :param other_opts: More options
            Elemements may be either:
                - CoAPOption datas
                    -> will be fed into a Opt() together with the Uri options
                - CoAPOptionList datas
                    -> will be combined with the Opt() within a All() template
        :type uri: str
        :type other_opts: tuple of more parameters
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
                assert not any(
                    isinstance(v, CoAPOptionUriPath) for v in other_opts
                )
                for elem in u.path.split("/"):
                    if elem:
                        opt.append(CoAPOptionUriPath(elem))
            if u.query:
                assert not any(
                    isinstance(v, CoAPOptionUriQuery) for v in other_opts
                )
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


class Link(list):
    """
    Class representing the link values for CoAP

    .. example:: coap://[adress][/uri]?[par_name]=[par_token]
    .. note:: In the whole class, the string representation of the link value
              got by parsing the payload of the CoAP packet is stored into the
              's' variable
    """

    __re_uri = re.compile(r"<([^>]*)>")
    __re_par_name = re.compile(r";([0-9A-Za-z!#$%&+^_`{}~-]+)(=?)")
    __re_ptoken = re.compile(r"[]!#$%&'()*+./:<=>?@[^_`{|}~0-9A-Za-z-]+")

    class FormatError(Exception):
        """
        Error thrown when there is a format error during parsing the uri value
        """
        pass

    @typecheck
    def is_compiled_regex(arg):
        """
        Check if a parameter is a valid regex compiled object.
        This function is used for the typechecker decorator.

        :return: True if a valid compiled regex, False if not
        :rtype: bool
        """
        return all((
            arg is not None,
            isinstance(arg, type(re.compile('dummy_pattern')))
        ))

    @typecheck
    def __init__(self, pl: bytes):
        """
        Initialize the link representation

        :param pl: The payload of the CoAP layer
        :type pl: bytes
        """

        @typecheck
        def error(msg: str, in_string=None):
            """
            Function to manage format errors

            :param msg: The string that we were seeking
            :param in_string: The object in which we were seeking
            :type msg: str
            :type in_string: anything

            :raises FormatError: Always raises this exception because it's the
                                 main purpose of this function
            """
            if in_string:
                raise self.FormatError("%s in %r" % (msg, in_string))
            else:
                raise self.FormatError("%s at %r..." % (msg, s[:40]))

        @typecheck
        def have(string: str) -> bool:
            """
            Check if the link value contains the entered parameter

            :param string: The string to seek in the link value
            :type string: str

            :return: True if the string is contained into the link value
            :rtype: bool
            """
            return s and s.startswith(string)

        @typecheck
        def percent_unquote(string: str) -> str:
            """
            Replace '%xx' url encoded special characters by their string value

            :param string: The uri value from which we will replace those
            :type string: str

            :raises FormatError: If the urllib was unable to replace the '%xx'
                                 characters

            :return: The uri with the special characters as normal char
            :rtype: str
            """
            try:
                return urllib.parse.unquote(string, errors='strict')
            except UnicodeDecodeError as e:
                error(str(e), string)

        # Try to parse the given payload into utf-8 string representation
        try:
            s = str(pl, 'utf-8')
        except UnicodeDecodeError as e:
            error(str(e), pl)

        # Match object used here
        mo = None

        @typecheck
        def consume(pattern: either(str, is_compiled_regex), subject: str):
            """
            Consume a part of the link value (stored into s variable)

            :param pattern: The pattern to consume
            :param subject: The name of the subject to consume
            :type pattern: either(str, _sre.SRE_Pattern)
            :type subject: str
            """

            # Get the extern s (for uri current value) and mo (match object)
            nonlocal s, mo

            # If the pattern is a string
            if isinstance(pattern, str):
                if s.startswith(pattern):
                    s = s[len(pattern):]
                    return

            # If the pattern is a compiled regex
            else:
                mo = re.match(pattern, s)
                if mo:
                    s = s[mo.end(0):]
                    return

            # If it didn't match with the current uri value
            error("malformed %s" % subject)

        # If it managed to get a string (uri value) from the payload
        if s:
            while True:

                # Link-value
                consume(self.__re_uri, 'uri')

                # Get the uri value without the encoded special chars
                uri = percent_unquote(mo.group(1))

                # Store the value of it
                link_value = self.LinkValue(uri)

                # While there is a ";" we can process the parameter
                while have(";"):

                    # Link-param
                    consume(self.__re_par_name, 'parmname')

                    # Get the name of the parameter
                    name = mo.group(1)

                    # If no value associated to it
                    if not mo.group(2):
                        value = None

                    # If it does have a value associated
                    elif have('"'):

                        # Quoted-string => Read and unquote it
                        value = []
                        esc = False

                        # Parse the whole uri left
                        for i in range(1, len(s)):

                            # Get each character
                            c = s[i]

                            # If it's not escaped
                            if not esc:

                                # If it's escaped now
                                if c == '\\':
                                    esc = True

                                # End of string
                                elif c == '"':
                                    break

                                # Other chars
                                # TODO: Normalise LWS
                                else:
                                    value.append(c)

                            # If it is escaped
                            else:
                                esc = False

                                # Quoted char
                                if c == '"' or c == '\\':
                                    value.append(c)

                                # Was an unquoted \
                                else:
                                    value.append('\\' + c)

                        # Error: unterminated quoted-string
                        else:
                            error(
                                "attribute value for %r is %s"
                                %
                                (
                                    name,
                                    'an unterminated quoted-string'
                                )
                            )

                        # Transform the value char list into a single string
                        value = ''.join(value)

                        # If still empty
                        if not value:
                            error("attribute value for %r is empty" % name)

                        # Consume the read part
                        s = s[i+1:]

                    # If it doesn't begin with a quote, it's a token
                    else:

                        # Consume it
                        consume(self.__re_ptoken, 'ptoken')

                        # And generate its value
                        value = percent_unquote(mo.group(0))

                    # Add the link value pair
                    link_value.append((name, value))

                # In the end, append the link value to the link list
                self.append(link_value)

                # If we finished reading the whole uri, s is now empty
                if not s:
                    break

                # Next link-value
                consume(",", "delimiter, expected ','")

    class LinkValue(list):
        """
        A class representing the link values which consist into a parameter
        name associated a parameter value
        """

        @typecheck
        def __init__(self, uri: str):
            """
            Initialize the link value object

            :param uri: The basic uri
            :type uri: str
            """
            self.uri = uri

        @typecheck
        def get(
            self,
            par_name: str,
            testcase: optional(CoAPTestCase) = None
        ) -> optional(str):
            """
            Get the value of a link value from its parameter name

            :param par_name: The parameter name
            :param testcase: The TestCase object to put its verdict to 'fail'
            :type par_name: str
            :type testcase: optional(CoAPTestCase)

            :return: The parameter value associated to this parameter name if
                     one found, None if none found
            :rtype: optional(str)
            """

            # The result to return, None at the beginning to check if a link
            # value has multiple values for a single parameter name
            result = None

            # For each couple (name => value) inside this list
            for name, value in self:

                # If the parameter name is found
                if name == par_name:

                    # If no result found until here, ok and put it
                    if result is None:
                        result = value

                    # If a value was already put and another one if found
                    else:
                        msg = (
                            "link-value contains multiple %r parameters"
                            %
                            par_name
                        )

                        # If a test case object is given, its verdict fails
                        if testcase:
                            testcase.set_verdict('fail', msg)
                        else:
                            raise Exception(msg)

            # Return the value if one found, if none found just return None
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

        :param frames: The frame to put into the tracker lists
        :type frame: [Frame]
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

    .. note::
        - As we only run a test case into analyze function, we don't need to
          group them by pair anymore
        - We still need this at least for putting the next variable which links
          conversations between them
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

    from ttproto.core.lib.ports.pcap import PcapReader
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
