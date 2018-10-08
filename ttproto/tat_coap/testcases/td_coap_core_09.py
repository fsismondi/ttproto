#!/usr/bin/env python3

from ..common import *


class TD_COAP_CORE_09(CoAPTestCase):
    """
---
TD_COAP_CORE_09:
    cfg: CoAP_CFG_BASIC
    not: Steps 3 and 4 may occur out-of-order
    obj: Perform GET transaction with separate response (CON mode, no
        piggyback)
    pre: Server offers a resource /separate which is not served immediately
        and which therefore is not acknowledged in a piggybacked way.
    ref: '[COAP] 5.8.1, 5.2.2'
    seq:
    -   s: "Client is requested to send a confirmable GET request to
            server\u2019s resource"
    -   c:
        - 'The request sent by the client contains:'
        -   - Type = 0 (CON)
            - Code = 1 (GET)
            - "Client-generated Message ID (\u2794 CMID)"
            - Uri-Path option "separate"
            - "Client-generated Token (\u2794 CTOK)"
    -   c:
        - 'Server sends response containing:'
        -   - Type = 2 (ACK)
            - Code = 0
            - Message ID = CMID
            - Empty Payload
    -   n: Some time (a couple of seconds) elapses.
    -   c:
        - 'Server sends response containing:'
        -   - Type = 0 (CON)
            - Code = 2.05 (Content)
            - "Server-generated Message ID (\u2794 SMID)"
            - Token = CTOK
            - Content-format option
            - Non-empty Payload
    -   c:
        - 'Client sends response containing:'
        -   - Type = 2 (ACK)
            - Code = 0
            - Message ID = SMID
            - Empty Payload
    -   v: Client displays the response
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
        return [
            CoAP(type='con', code='get', opt=Opt(CoAPOptionUriPath("separate")))
        ]

    def run(self):
        self.match("client", CoAP(type="con", code="get", opt=self.uri("/separate")))
        CMID = self.coap["mid"]
        CTOK = self.coap["tok"]

        self.next()

        # FIXME: may be out-of-order
        if not self.match("server", CoAP(type="ack", code=0, mid=CMID, pl=b"")):
            raise self.Stop()

        self.next()

        # FIXME: this is in a different conversation
        self.match("server", CoAP(type="con", code=2.05))
        self.match("server", CoAP(tok=CTOK, pl=Not(b''), opt=Opt(CoAPOptionContentFormat())), "fail")
        SMID = self.coap["mid"]

        self.next()

        self.match("client", CoAP(type="ack", code=0, mid=SMID, pl=b""))
