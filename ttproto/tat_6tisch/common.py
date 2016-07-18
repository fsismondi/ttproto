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
import traceback

from .templates import *
from ttproto.core.analyzer import TestCase, Verdict, is_verdict
from ttproto.core.dissector import Frame
#from ttproto.core.templates import All, Not, Any, Length
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


# TODO define another inspection & labeling mechanism more modular using class Value
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


class SixTischTestCase(TestCase):
    """
    The test case extension representing a SixTischTestCase test case
    """

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
        #
        # # Initialize its verdict instance and its list of frame
        self.__verdict = Verdict()
        self.__frames = frame_list

        self.__text = ''
        self.__failed_frames = set()
        self.__review_frames_log = []
        self.__exceptions = ''


    @typecheck
    def match(
        self,
        sender: either(str, type(None)),
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

        # If it matched, return True
        return True

    @typecheck
    def next(self, optional: bool = False):
        """
        Switch to the next frame

        :param optional: If we have to get a next frame or not
        :type optional: bool
        """
        pass


    @typecheck
    def next_skip_ack(self, optional: bool = False):
        """
        Call self.next() but skips possibly interleaved ACKs

        :param optional: If we have to get a next frame or not
        :type optional: bool
        """

        pass

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

        pass

    @typecheck
    def run_test_case(self) -> (str, list_of(int), str, str):
        """
        Run the test case

        :return: A tuple with the informations about the test results which are
                 - The verdict as a string
                 - The list of the result important frames
                 - A string for extra informations
                 - A string representing the exceptions that could have occured
        :rtype: (str, [int], str, str)
        """

        try:

            # Run the test case
            self.run()


        except self.Stop:
                self.set_verdict('none', 'no match')

        except Exception:

                self.set_verdict('error', 'unhandled exception')
                exception = traceback.format_exc()
                self.__exceptions += exception
                self.log(exception)

        # Return the results
        return (
            self.__verdict.get_value(),
            list(self.__failed_frames),
            self.__text,
            self.__exceptions
        )




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

    # from ttproto.core.lib.ports.pcap import PcapReader
    # frame_list = Frame.create_list(PcapReader(filename))
    #
    # for frame in frame_list:
    #     duct_tape(frame)
    #
    # tracker = CoAPTracker(frame_list)
    # conversations = tracker.conversations
    # ignored = tracker.ignored_frames
    # print('#####')
    # print('##### Conversations')
    # print(conversations)
    # print('#####')
    # print('##### Ignored')
    # print(ignored)
    # print('#####')
    # print('##### Conversations by pair')
    # conversations_by_pair = group_conversations_by_pair(conversations)
    # print(conversations_by_pair)
    # print('#####')
