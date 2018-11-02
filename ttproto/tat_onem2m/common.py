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

from .templates import *
from ttproto.core.analyzer import TestCase, is_protocol, Node, Conversation, Capture
from ttproto.core.dissector import Frame
from ttproto.core.templates import All, Not, Any, Length
from ttproto.core.typecheck import *
from ttproto.core.lib.all import *
from urllib import parse
from ttproto.core.exceptions import Error


# CoAP constants
RESPONSE_TIMEOUT = 2
RESPONSE_RANDOM_FACTOR = 1.5
MAX_RETRANSMIT = 4
MAX_TIMEOUT = 10 + round(
        (RESPONSE_TIMEOUT * RESPONSE_RANDOM_FACTOR) * 2**MAX_RETRANSMIT
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
        Get the nodes of this test case. This has to be be implemented into
        each test cases class.

        :return: The nodes of this TC
        :rtype: [Node]

        .. note:: For CoAP it is simpler so we can define this function in this
                  class but for other protocols it can happend that we have to
                  define this inside each TC
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
            expected_frames_pattern:list_of(Value)
    ) -> (list_of(Conversation), list_of(Frame)):
        """
        Preprocess and filter the frames of the capture into test case related
        conversations.

        :param Capture: The capture which will be filtered/preprocessed
        :return: list of conversations and list of ignored frames
        """

        protocol =CoAPTestCase.get_protocol()
        nodes = CoAPTestCase.get_nodes_identification_templates()

        conversations = []
        ignored = []

        # TODO what happens if no protocol declared on the test case?
        if not nodes or len(nodes) < 2:
            raise ValueError(
                'Expected at least two nodes declaration from the test case'
            )
        if not protocol:
            raise ValueError(
                'Expected a protocol under test declaration from the test case'
            )

        # If there is no stimuli at all
        if not expected_frames_pattern or len(expected_frames_pattern) == 0:
            raise NoStimuliFoundForTestcase(
                'Expected stimuli declaration from the test case'
            )

        # Get the frames related with the protocol under test
        frames, ignored = Frame.filter_frames(capture.frames, protocol)

        # Get a counter of the current stimuli
        sti_count = 0
        current_conversation = None
        nb_stimulis = len(expected_frames_pattern)
        for frame in frames:

            # If the frame matches a stimuli
            if expected_frames_pattern[sti_count].match(frame[protocol]):

                # If it's the first stimuli
                if sti_count == 0:

                    # If there is already a conversation pending, save it
                    if current_conversation:
                        self._conversations.append(current_conversation)

                    # Get the nodes as a list of nodes
                    # TODO already done at begining. why isnde the iteeration?
                    # nodes = testcase.get_nodes_identification_templates()

                    # And create the new one
                    current_conversation = Conversation(nodes)

                # If intermediate stimulis, just increment the counter
                sti_count = (sti_count + 1) % nb_stimulis

            # If there is a current_conversation, put the frame into it
            if current_conversation:
                current_conversation.append(frame)

            # If no conversation pending
            else:
                ignored.append(frame)

        # At the end, if there is a current conversation pending, close it
        if current_conversation:

            # If not all stimulis were consumed
            if sti_count != 0:
                raise FilterError(
                    'Not all stimulis were consumed, %d left and next one should have been %s'
                    %
                    (
                        nb_stimulis - sti_count,
                        expected_frames_pattern[sti_count]
                    )
                )

            # Close the current conversation by adding it to list
            conversations.append(current_conversation)

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


if __name__ == "__main__":
    pass
