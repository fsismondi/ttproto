#!/usr/bin/env python3

from ..common import *


class TD_COAP_ANALYSIS_1 (CoapPrivacyTestCase):
    """
    Identifier:
        TD_COAP_ANALYSIS_1
    Objective:
        Analyse all GET messages and look for keywords refering to potential private sensitive information.

    """

    @classmethod
    @typecheck
    def get_stimulis(cls) -> list_of(Value):
        """
        Get the stimulis of this test case. This has to be be implemented into
        each test cases class.

        :return: The stimulis of this TC
        :rtype: [Value]

        .. warning::
            For the moment, we didn't manage to generate packets with the
            wanted size so we just don't take them into account
        """
        return []


    @classmethod
    @typecheck
    def get_nodes_identification_patterns(cls) -> list_of(Node):
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

    def run(self):
        while(self.next):
            if self.match('client', CoAP(), 'pass' ):
                print("passed :d")

