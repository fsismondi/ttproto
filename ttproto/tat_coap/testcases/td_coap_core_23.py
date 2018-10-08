#!/usr/bin/env python3

from ..common import *


class TD_COAP_CORE_23(CoAPTestCase):
    """
---
TD_COAP_CORE_23:
    cfg: CoAP_CFG_BASIC
    obj: Perform PUT transaction containing the If-None-Match option (CON
        mode)
    pre:
    - Server offers a /create1 resource, which does not exist and can be
        created by the client
    - Client & server support If-Non-Match
    ref: '[COAP] 5.8.1, 5.10.7, 5.10.10, 12.1.12'
    seq:
    -   n: single creation
    -   s: "Client is requested to send a confirmable PUT request to server\
            \u2019s resource so as to atomically create the resource."
    -   c:
        - 'The request sent by the client contains:'
        -   - Type = 0 (CON)
            - Code = 3 (PUT)
            - "Client-generated Message ID (\u2794 CMID)"
            - "Client-generated Token (\u2794 CTOK)"
            - Content-format option
            - Uri-Path option "create1"
            - Option Type=If-None-Match
            - An arbitrary payload
    -   c:
        - 'Server sends response containing:'
        -   - Code = 2.01 (Created)
            - Message ID = CMID, Token = CTOK
            - Content-format option if payload non-empty
            - Empty or non-empty Payload
    -   v: Client displays the response and the server created a new resource
    -   n: concurrent creations
    -   s: "Client is requested to send a confirmable PUT request to server\
            \u2019s resource so as to atomically create the resource."
    -   c:
        - 'The request sent by the client contains:'
        -   - Type = 0 (CON)
            - Code = 3 (PUT)
            - "Another client-generated Message ID \u2260 CMID (\u2794 CMID2)"
            - "Client-generated Token which may or may not be \u2260 CTOK\
                \ (\u2794 CTOK2)"
            - Content-format option
            - Uri-Path option "create1"
            - Option Type=If-None-Match
            - An arbitrary payload
    -   c:
        - 'Server sends response containing:'
        -   - Code = 4.12 (Precondition Failed)
            - Message ID = CMID2, Token = CTOK2
            - Optional Content-format option
            - Empty or non-empty Payload
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

        .. note::
            Check the number/value of the uri query options or not?
        """
        return [
            CoAP(type='con', code='put', opt=Opt(CoAPOptionUriPath("create1"))),  # Step 1
            CoAP(type='con', code='put', opt=Opt(CoAPOptionUriPath("create1")))  # Step 5
        ]

    request_uri = "/create1"

    def run(self):
        # Part A
        # Step 2
        self.match("client", CoAP(type="con", code="put",
                                  opt=Opt(
                                      CoAPOptionContentFormat(),
                                      CoAPOptionUriPath(self.request_uri[1:]),
                                      CoAPOptionIfNoneMatch(),
                                  ),
                                  pl=Not(b"")))

        CMID = self.coap["mid"]
        CTOK = self.coap["tok"]

        self.next_skip_ack()
        # Step 3
        if not self.match("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                         code=2.01, mid=CMID, tok=CTOK)):
            raise self.Stop()

        if self.match("server", CoAP(pl=Not(b"")), None):
            self.match("server", CoAP(opt=Opt(CoAPOptionContentFormat()), ), "fail")

        self.next_skip_ack(optional=True)

        # Part B
        # Step 6
        self.match("client", CoAP(type="con",
                                  code="put",
                                  opt=Opt(
                                      CoAPOptionContentFormat(),
                                      CoAPOptionUriPath(self.request_uri[1:]),
                                      CoAPOptionIfNoneMatch(),
                                  ),
                                  pl=Not(b"")))
        CMID2 = self.coap["mid"]
        CTOK2 = self.coap["tok"]
        if CMID2 != b"":
            if CMID2 == CMID:
                self.set_verdict("fail", "Message ID should be different")
        if CTOK2 != b"":
            if CTOK2 == CTOK:
                self.set_verdict("fail", "Token should be different")

        self.next_skip_ack()
        # Step 7
        if not self.match("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                         code=4.12,
                                         mid=CMID2,
                                         tok=CTOK2), 'fail'):
            raise self.Stop()

        self.next_skip_ack(optional=True)
