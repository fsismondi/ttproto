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
from ttproto.core.typecheck import typecheck, tuple_of, optional, anything, list_of
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


class SixlowpanTestCase(TestCase):
    """
    The test case extension representing a Sixlowpan test case
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
        return SixLowpanIPHC

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
        :return:
        """

        protocol = SixlowpanTestCase.get_protocol()
        nodes = TestCase.get_nodes_identification_templates()
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
        # If there is no stimuli at all
        if not expected_frames_pattern or len(expected_frames_pattern) == 0:
            raise NoStimuliFoundForTestcase(
                'Expected stimuli declaration from the test case'
            )

        # Get the frames filtered on the protocol
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
                        stimulis[sti_count]
                    )
                )

            # Close the current conversation by adding it to list
            conversations.append(current_conversation)

        return conversations, ignored
