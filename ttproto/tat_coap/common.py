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
from collections import OrderedDict
from .templates import *
from ttproto.core.analyzer import TestCase, is_protocol, Node, Conversation, Capture
from ttproto.core.dissector import Frame
from ttproto.core.templates import *
from ttproto.core.typecheck import typecheck
from ttproto.core.lib.all import *
from urllib import parse
from ttproto.core.exceptions import Error

# CoAP constants
RESPONSE_TIMEOUT = 2
RESPONSE_RANDOM_FACTOR = 1.5
MAX_RETRANSMIT = 4
MAX_TIMEOUT = 10 + round(
    (RESPONSE_TIMEOUT * RESPONSE_RANDOM_FACTOR) * 2 ** MAX_RETRANSMIT
)


class NoStimuliFoundForTestcase(Error):
    """
    Error raised when no stimuli was defined for the testcase
    """
    pass


class FilterError(Error):
    """
    The error thrown when an error occurs into Filter object during its run
    """
    pass


class CoAPTestCase(TestCase):
    """
    The test case extension representing a CoAP test case
    """

    # Some default parameters
    reverse_proxy = False
    urifilter = False

    @classmethod
    @typecheck
    def get_protocol(cls) -> is_protocol:
        """
        Get the protocol corresponding to this test case. This has to be
        implemented into the protocol's common test case class.

        :return: The protocol on which this TC will occur
        :rtype: Value
        """
        return CoAP

    @classmethod
    @typecheck
    def get_nodes_identification_templates(cls) -> list_of(Node):
        """
        Get the nodes of CoAP test case.

        :return: The nodes involved in the CoAP test case
        :rtype: [Node]

        .. note:: For CoAP it is simple so we can define general behaviour for all CoAP test cases,
                  for other protocols this may have to be defined in subclasses (specific test case scenario).
        """
        return [
            Node('client', UDP(dport=5683)),
            Node('server', UDP(sport=5683))
        ]

    @classmethod
    @typecheck
    def preprocess(
            cls,
            capture: Capture,
            expected_frames_pattern: list_of(Value)
    ) -> (list_of(Conversation), list_of(Frame)):
        """
        Pre-processes and filters the frames of the capture into test case related
        conversations.

        This method depends on the protocol features, so it cannot be
        implemented in a generic way (in super class TestCase)

        :param Capture: The capture which will be filtered/preprocessed
        :return: list of conversations and list of ignored frames
        """

        if not expected_frames_pattern:  # If there is no stimuli at all
            raise NoStimuliFoundForTestcase(
                'Expected stimuli declaration from the test case for running pre-process and filtering of frames'
            )
        conversations_created_by_token, ignored = cls.extract_all_coap_conversations(capture)
        conversations_correlated_for_testcases = cls.correlate(conversations_created_by_token, expected_frames_pattern)
        return conversations_correlated_for_testcases, ignored

    @classmethod
    @typecheck
    def correlate(cls, conversations: list_of(Conversation),
                  expected_frames_pattern: list_of(Value)) -> list_of(Conversation):
        """
        Correlates related conversations.
        Conversations related to a test case, having several
        stimulis, are merged into one.
        This method relies on the given stimulis as frames pattern to determine which
        conversations are related for the test case.

        When having several stimulis, we rely on timestamp to have the wanted order.
        A whole related conversation will be fully inserted BEFORE
        the first frame of the base conversation having a timestamp
        greater than the timestamp of the related one.

        Simple example with only one stimulis :

        Here is a simple example with a single stimulis for TD_COAP_CORE_04.
        The stimulis for this TC is a confirmable POST request on resource /test
        with empty or non-empty payload.
        I.e CoAP(type='con', code='post', opt=Opt(CoAPOptionUriPath("test")).

        Let's say we have a 4 conversations in the given list of conversations:

        # python3 -i console.py
        >>> from pprint import pprint
        >>> c = Capture('tests/test_dumps/preprocess/coap/Two_tc_two_times_each_with_overlap.pcap')
        >>> pprint(c.frames)
        [<Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON mid 19207] GET /separate, tok 00 00 5f 6a >,
         <Frame   2: [127.0.0.1 -> 127.0.0.1] CoAP [ACK mid 19207] Empty >,
         <Frame   3: [127.0.0.1 -> 127.0.0.1] CoAP [CON mid 56421] 2.05 Content , tok 00 00 5f 6a >,
         <Frame   4: [127.0.0.1 -> 127.0.0.1] CoAP [ACK mid 56421] Empty >,
         <Frame   5: [127.0.0.1 -> 127.0.0.1] CoAP [CON mid 4146] POST /test, tok 28 6b 05 55 ca 09 29 ae >,
         <Frame   6: [127.0.0.1 -> 127.0.0.1] CoAP [ACK mid 4146] 2.01 Created /location1/location2/location3, tok 28 6b 05 55 ca 09 29 ae >,
         <Frame   7: [127.0.0.1 -> 127.0.0.1] CoAP [CON mid 10512] GET /separate, tok 00 00 5b e1 >,
         <Frame   8: [127.0.0.1 -> 127.0.0.1] CoAP [ACK mid 10512] Empty >,
         <Frame   9: [127.0.0.1 -> 127.0.0.1] CoAP [CON mid 58373] POST /test, tok e4 d8 1e c4 96 6e f9 20 >,
         <Frame  10: [127.0.0.1 -> 127.0.0.1] CoAP [ACK mid 58373] 2.01 Created /location1/location2/location3, tok e4 d8 1e c4 96 6e f9 20 >,
         <Frame  11: [127.0.0.1 -> 127.0.0.1] CoAP [CON mid 56422] 2.05 Content , tok 00 00 5b e1 >,
         <Frame  12: [127.0.0.1 -> 127.0.0.1] CoAP [ACK mid 56422] Empty >]



        conversations[0] = [
            < [Client 1 -> Server] CoAP [CON 19207] GET /separate >
            < [Server -> Client 1] CoAP [ACK 19207] Empty >
            < [Server -> Client 1] CoAP [CON 56421] 2.05 Content >
            < [Client 1 -> Server] CoAP [ACK 56421] Empty >
        ]

        conversations[1] = [
            < [Client 1 -> Server] CoAP [CON 4146] POST /test>
            < [Server -> Client 1] CoAP [ACK 4146] 2.01 Created>
        ]

        conversations[2] = [
            < [Client 1 -> Server] CoAP [CON 10512] GET /separate>
            < [Server -> Client 1] CoAP [ACK 10512] Empty >
            < [Server -> Client 1] CoAP [CON 56422] 2.05 Content >
            < [Client 1 -> Server] CoAP [ACK 56422] Empty >
        ]

        conversations[3] = [
            < [Client 1 -> Server] CoAP [CON 58373] POST /test>
            < [Server -> Client 1] CoAP [ACK 58373] 2.01 Created>
        ]

        From a list of those conversations and the stimulis of TD_COAP_CORE_04
        as argument, this method will return a new list of conversations
        containing only the second (i.e conversations[1]) and the fourth
        conversations (conversations[3]) because only those correspond to the
        stimulis.

        The two others conversations are ignored.
        Of course if the expected_frames_pattern argument would be the
        stimulis of TD_COAP_CORE_09 instead of CORE_04, we would return a list
        contaings conversations[0] and conversations[2] because those matches
        with the stimulis of TD_COAP_CORE_09.
        This stimulis is a GET request on /separate,
        i.e CoAP(type='con', code='get', opt=Opt(CoAPOptionUriPath("separate")).

        If we would pass both stimulis of TD_COAP_CORE_09 and TD_COAP_CORE_04,
        all conversations would be returned.

        Simple example with several stimulis :

        Here is a simple example with a single stimulis for TD_COAP_CORE_07.
        The first stimulis for this TC is a client sending a GET request with
        observe option to receive notification from the server, on resource /obs.

        The second stimulis is another CoAP client doing a DELETE request on the
        same resource.

        Let's say we extracted 5 conversations in the given pcap.

        conversations[0] = [
            <Frame   1: [Client 1 -> Server] CoAP [CON 45525] GET /obs>
            <Frame   2: [Server -> Client 1] CoAP [ACK 45525] 2.05 Content >
            <Frame   7: [Server -> Client 1] CoAP [CON 9255] 2.05 Content >
            <Frame   8: [Client 1 -> Server] CoAP [ACK 9255] Empty >
            <Frame  10: [Server -> Client 1] CoAP [CON 9256] 4.04 Not Found >
            <Frame  11: [Client 1 -> Server] CoAP [ACK 9256] Empty >
        ]

        conversations[1] = [
            <Frame   3: [Client 1 -> Server] CoAP [CON 10074] POST /test>
            <Frame   4: [Server -> Client 1] CoAP [ACK 10074]
                                    2.01 Created /location1/location2/location3>
        ]

        conversations[2] = [
            <Frame   5: [Client 1 -> Server] CoAP [CON 15501] GET /test>
            <Frame   6: [Server -> Client 1] CoAP [ACK 15501] 2.05 Content >
        ]

        conversations[3] = [
            <Frame   9: [Client 1 -> Server] CoAP [CON 51892] DELETE /obs>
            <Frame  12: [Server -> Client 1] CoAP [ACK 51892] 2.02 Deleted >
        ]

        conversation[4] = [
            <Frame  13: [Client 1 -> Server] CoAP [CON 65335] GET /test>
            <Frame  14: [Server -> Client 1] CoAP [ACK 65335] 2.05 Content >
        ]

        The first conversations (conversations[0]) match the first stimuli.
        The fourth conversation (conversations[3]) match the second stimuli.

        The other conversation don't match any stimulis, hence are discarded if
        the given stimulis are the stimulis is TD_COAP_OBS_07.

        As those two conversations above belong to the same instance
        of the same TC, they will be merged into a single conversation, that is:

        <Frame   1: [Client 1 -> Server] CoAP [CON 45525] GET /obs>
        <Frame   2: [Server -> Client 1] CoAP [ACK 45525] 2.05 Content >
        <Frame   7: [Server -> Client 1] CoAP [CON 9255] 2.05 Content >
        <Frame   8: [Client 1 -> Server] CoAP [ACK 9255] Empty >
        <Frame   9: [Client 2 -> Server] CoAP [CON 51892] DELETE /obs>
        <Frame  12: [Server -> Client 2] CoAP [ACK 51892] 2.02 Deleted >
        <Frame  10: [Server -> Client 1] CoAP [CON 9256] 4.04 Not Found >
        <Frame  11: [Client 1 -> Server] CoAP [ACK 9256] Empty >

        This method return a list_of(Conversation) because a futur feature that
        will allow to execute tests from a large pcap having several TC,
        with single TC able to being executed several times.
        Each different instance of the TC will have a different Conversation.

        """
        # TODO Adding an example in the documentation above.
        conversations_matching_stimulis = cls.__get_all_matching_conversations(
            conversations,
            expected_frames_pattern
        )
        conversations_to_merge = cls.__get_conversation_to_merge(
            conversations_matching_stimulis,
            expected_frames_pattern
        )
        return cls.__merge_all_conversations_to_merge(conversations_to_merge)

    @classmethod
    @typecheck
    def __merge_all_conversations_to_merge(
            cls,
            conversations_to_merge: list_of(list_of(Conversation))
    ) -> list_of(Conversation):
        """
        A list of list of conversation that must be merged together.
        That is, we merge all conversations of in the same "inner list" into one,
        and return the list of those merged conversations.
        """
        all_merged_conversations = []

        for list_of_related_conversations in conversations_to_merge:
            merged_conversation = cls.__merge_conversations(
                list_of_related_conversations)
            all_merged_conversations.append(merged_conversation)

        return all_merged_conversations

    @classmethod
    @typecheck
    def __merge_conversations(
            cls,
            conversations_to_merge: list_of(Conversation)
    ) -> Conversation:
        """
        Merge the given conversations into a single one.
        The given conversation should be belong to the same instance of the same TC.
        """
        nodes = cls.get_nodes_identification_templates()
        merged_conversation = Conversation(nodes)

        # The list of conversations already merged,
        # used to avoid processing two time the same one several times.
        added_in_merged_conv = list()

        for conv in conversations_to_merge:
            if conv in added_in_merged_conv:
                continue  # Already treated
            for frame in conv:
                for other_conv in conversations_to_merge:
                    if other_conv is not conv \
                            and other_conv[0].timestamp < frame.timestamp \
                            and other_conv not in added_in_merged_conv:
                        # We check at the first frame of other conversation to see
                        # if there is any correlation.
                        for other_frame in other_conv:
                            merged_conversation.append(other_frame)
                            added_in_merged_conv.append(other_conv)
                merged_conversation.append(frame)
            added_in_merged_conv.append(conv)

        return merged_conversation

    @classmethod
    @typecheck
    def __get_all_matching_conversations(
            cls,
            conversations: list_of(Conversation),
            expected_frames_pattern: list_of(Value)
    ) -> list_of(Conversation):
        """

        Retrieve a list of all conversations that correspond to any stimulis
        of the test cases (see get_stimulis()).

        """
        conversations_to_merge = list()

        for current_conversation in conversations:
            for frame in current_conversation:
                # conv_already_added is here to avoid doing useless iteration
                # and adding several times the same conv.
                conv_already_added = False
                for stimulis in expected_frames_pattern:
                    if frame[CoAP] in stimulis:
                        # We only look at the first frame as stimulis are
                        # Always query from client.
                        conversations_to_merge.append(current_conversation)
                        conv_already_added = True
                        break
                if conv_already_added:
                    break

        return conversations_to_merge

    @classmethod
    @typecheck
    def __get_conversation_to_merge(
            cls,
            conversations: list_of(Conversation),
            expected_frames_pattern: list_of(Value)) \
            -> list_of(list_of(Conversation)):
        """
        Retrieve a list 'outer' of list 'inter' with each conversations inside
        those inter lists having to be merged together. That is, conversations
        must be merged together if they belong to the same instance of the same
        TC described with expected_frames_pattern.

        This method return a list of list and not a simple list,
        because the user may execute several times the same test.
        Also, if running passive test from a pcap, this pcap may contains
        several conversations related to the same TC.
        """
        # TODO example
        conversations_maching_a_stimulis = conversations
        all_convs_to_merge = []
        current_convs_to_merge = []

        for conv in conversations_maching_a_stimulis:
            if conv[0][CoAP] in expected_frames_pattern[0] \
                    and len(current_convs_to_merge) == 0:
                current_convs_to_merge.append(conv)
            elif conv[0][CoAP] in expected_frames_pattern[0]:
                all_convs_to_merge.append(current_convs_to_merge)
                current_convs_to_merge = []
                current_convs_to_merge.append(conv)
            else:
                current_convs_to_merge.append(conv)

        if current_convs_to_merge not in all_convs_to_merge:
            all_convs_to_merge.append(current_convs_to_merge)

        return all_convs_to_merge

    @classmethod
    @typecheck
    def extract_all_coap_conversations(
            cls,
            capture: Capture) -> (list_of(Conversation), list_of(Frame)):

        protocol = cls.get_protocol()
        nodes = cls.get_nodes_identification_templates()

        conversations = []
        ignored = []

        # TODO what happens if no protocol declared on the test case?
        if not nodes or len(nodes) < 2:
            raise ValueError(
                'Expected at leaset two nodes declaration from the test case'
            )
        if not protocol:
            raise ValueError(
                'Expected a protocol under test declaration from the test case'
            )
        # Get the frames related with the protocol under test
        frames, ignored = Frame.filter_frames(capture.frames, protocol)

        # Map a token to the corresponding conversations.
        tkn_to_conv = OrderedDict()

        # Map a MID of a frame to it's containing token.
        # It's allow us to know to which conversation ACK frames belongs to
        # even though ACK do not contains token.
        mid_to_tkn = OrderedDict()

        # A set of CMID of messages for which we already saw an ACK.
        # This set allows use to detect duplicated ACK.
        acknowledged_CMID = set()

        for frame in frames:
            CMID = frame[CoAP]["mid"]
            CTOK = frame[CoAP]["tok"]

            if frame[CoAP]["type"] == 2 or frame[CoAP]["type"] == 3:
                if CMID in acknowledged_CMID:
                    # A duplicated ACK or RST
                    ignored.append(frame)
                    continue
                else:
                    acknowledged_CMID.add(CMID)
                    if CMID not in mid_to_tkn:
                        # An orphan ACK or RST
                        ignored.append(frame)
                    else:
                        tkn_to_conv[mid_to_tkn[CMID]].append(frame)
            else:
                if CTOK in tkn_to_conv:
                    tkn_to_conv[CTOK].append(frame)
                else:  # First time we encounter the token "CTOK".
                    conv = Conversation(nodes)
                    conv.append(frame)
                    tkn_to_conv[CTOK] = conv
                mid_to_tkn[CMID] = CTOK

        conversations = [tkn_to_conv[k] for k in tkn_to_conv.keys()]
        return conversations, ignored

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
                    self._frame is not None,
                    self._frame[CoAP] in CoAP(type='ack', code=0)
        )):
            self.next(optional)

    @property
    def coap(self) -> CoAP:
        """
        Get the coap layer of the current frame

        :return: The coap layer of the current frame
        :rtype: CoAP
        """
        return self._frame[CoAP]

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
                        s = s[i + 1:]

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


if __name__ == "__main__":
    pass
