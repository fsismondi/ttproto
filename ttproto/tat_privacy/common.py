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

from ttproto.core.analyzer import TestCase, is_protocol, Node, Conversation, Capture
from ttproto.core.dissector import Frame
from ttproto.core.templates import All, Not, Any, Length
from ttproto.core.typecheck import *
from ttproto.core.lib.all import *
from urllib import parse
from ttproto.core.exceptions import Error

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

class CoapPrivacyTestCase(TestCase):
    """
    The test case extension for privacy analysis on CoAP transactions.
    """

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
    def get_test_purpose(cls) -> str:
        """
        Get the purpose of this test case

        :return: The purpose of this test case
        :rtype: str
        """
        if cls.__doc__:
            save = False
            for line in cls.__doc__.splitlines():
                if line.startswith('Objective'):
                    ret = line.split('*')[1]
                    save = True
                elif line.startswith('Configuration'):
                    return ' '.join(ret.split())
                elif save:
                    ret += line
        return ''

    @classmethod
    @typecheck
    def preprocess(
            cls,
            capture: Capture,
            expected_frames_pattern:list_of(Value)
    ) -> (list_of(Conversation), list_of(Frame)):
        """
        Preprocess and filter the frames of the capture into test case related conversations.

        :param Capture: The capture which will be filtered/preprocessed
        :return:
        """

        # Get informations from the test case
        protocol = CoapPrivacyTestCase.get_protocol()
        nodes = CoapPrivacyTestCase.get_nodes_identification_templates()

        conversations = []
        ignored = []

        if not nodes or len(nodes) < 2:
            raise ValueError('Expected at leaset two nodes declaration from the test case')
        if not protocol:
            raise ValueError('Expected a protocol under test declaration from the test case')

        # Get protocol related frames
        frames, ignored = Frame.filter_frames(capture.frames, protocol)

        # For privacy we dont need a preprocess for splitting the frames into conversations, we just analize it all
        c = Conversation(nodes)
        for f in frames:
            c.append(f)
        conversations.append(c)

        return conversations, ignored
