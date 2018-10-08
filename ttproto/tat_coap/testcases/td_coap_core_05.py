#!/usr/bin/env python3
from ..common import *


class TD_COAP_CORE_05(CoAPTestCase):
    """
---
TD_COAP_CORE_05:
    cfg: CoAP_CFG_BASIC
    obj: Perform GET transaction (NON mode)
    pre: Server offers a /test resource with resource content is not empty
        that handles GET
    ref: '[COAP] 5.8.1, 5.2.3'
    seq:
    -   s:
        - 'Client is requested to send a GET request with:'
        -   - Type = 1 (NON)
            - Code = 1 (GET)
    -   c:
        - 'The request sent by the client contains:'
        -   - Type=1 and Code=1
            - "Client-generated Message ID (\u2794 CMID)"
            - "Client-generated Token (\u2794 CTOK)"
            - Uri-Path option "test"
    -   c:
        - 'Server sends response containing:'
        -   - Type = 1 (NON)
            - Code = 2.05 (Content)
            - "Server-generated Message ID (\u2794 SMID)"
            - Token = CTOK
            - Content-format option
    -   v: Client displays the received information
    """

    @classmethod
    @typecheck
    def get_stimulis(cls) -> list_of(Value):
        """
        Get the stimulis of this test case. This has to be be implemented into
        each test cases class.

        :return: The stimulis of this TC
        :rtype: [Value]
        """
        return [CoAP(type='non', code='get', opt=Opt(CoAPOptionUriPath("test")))]

    def run(self):
        self.match("client", CoAP(type="non", code="get", opt=self.uri("/test")))
        CTOK = self.coap["tok"]

        self.next()

        if self.match("server", CoAP(type="non", code=2.05, tok=CTOK, )):
            self.match("server", CoAP(opt=Opt(CoAPOptionContentFormat())), "fail")
