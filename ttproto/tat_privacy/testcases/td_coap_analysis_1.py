#!/usr/bin/env python3

from ..common import *

class TD_COAP_ANALYSIS_1 (CoapPrivacyTestCase):
    """
    Identifier:
        TD_COAP_ANALYSIS_1
    Objective:
        Analyse all GET messages and look for keywords referring to potential private sensitive information.

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



    def run(self):
        while self.next():
            self.match ("client", CoAP (type="con", code="get"))

