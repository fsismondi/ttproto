#!/usr/bin/env python3

from ..common import *


class TD_COAP_CORE_31(CoAPTestCase):
    """
---
TD_COAP_CORE_31:
    cfg: CoAP_CFG_BASIC
    obj: Perform CoAP Ping (CON mode)
    pre: (Should work with any CoAP server)
    ref: '[COAP] 4.3'
    seq:
    -   s:
        - 'Client is requested to send a "Ping" request with:'
        -   - Type = 0 (CON)
            - Code = 0 (empty)
    -   c:
        - 'The request sent by the client is four bytes and contains:'
        -   - Type=0 and Code=0
            - "Client-generated Message ID (\u2794 CMID)"
            - Zero-length Token
            - No payload
    -   c:
        - 'Server sends four-byte RST response containing:'
        -   - Type=3 and Code=0
            - Message ID = CMID
            - Zero-length Token
            - No payload
    -   v: Client displays that the "Ping" was successful
    """

    @classmethod
    @typecheck
    def get_stimulis(cls) -> list_of(Value):
        """
        Get the stimulis of this test case. This has to be be implemented into
        each test cases class.

        :return: The stimulis of this TC
        :rtype: [Value]

        .. note::
            Check the number/value of the uri query options or not?
        """
        return [
            CoAP(type='con', code=0)  # Step 1
        ]

    def run(self):
        self.match("client", CoAP(type="con", code=0, tok=b"", pl=b""))
        CMID = self.coap["mid"]

        self.next_skip_ack()

        if self.match("server", CoAP(type=3)):
            self.match("server", CoAP(code=0, tok=b"", pl=b"", ), "fail")
