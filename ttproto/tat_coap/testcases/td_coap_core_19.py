#!/usr/bin/env python3

from ..common import *


class TD_COAP_CORE_19(CoAPTestCase):
    """
---
TD_COAP_CORE_19:
    cfg: CoAP_CFG_BASIC
    obj: Perform POST transaction with responses containing several
         Location-Query options (CON mode)
    pre: Server accepts creation of new resource on uri /location-query,
        the location of the created resource contains two query parameters
        ?first=1&second=2
    ref: '[COAP] 5.8.1, 5.10.8, 5.9.1.1'
    seq:
    -   s: "Client is requested to send a confirmable POST request to server\
            \u2019s resource"
    -   c:
        - 'The request sent by the client contains:'
        -   - Type = 0 (CON)
            - Code = 2 (POST)
            - "Client-generated Message ID (\u2794 CMID)"
            - "Client-generated Token (\u2794 CTOK)"
            - Content-format option
            - Empty or non-empty Payload
            - Uri-Path option "location-query"
    -   c:
        - 'Server sends response containing:'
        -   - Code = 2.01 (Created)
            - Message ID = CMID, Token = CTOK
            - Content-format option if payload non-empty
            - Zero or more Location-path options
            - Empty or non-empty Payload
        - 'and two options of type Location-Query, with the values (none
            of which contains a "?" or "&"):'
        -   - first=1
            - second=2
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
            CoAP(type='con', code='post', opt=Opt(CoAPOptionUriPath("location-query")))
        ]

    def run(self):
        self.match("client", CoAP(type="con",
                                  code="post",
                                  opt=self.uri(
                                      "/location-query",
                                      CoAPOptionContentFormat(),
                                  )))
        CMID = self.coap["mid"]
        CTOK = self.coap["tok"]

        self.next_skip_ack()
        # TODO: generate a fail if we have a '&' or '?' or '.' or '..' in the CoAPOptionLocationQuery ? see 5.10.7
        self.match("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                  code=2.01,
                                  mid=CMID,
                                  tok=CTOK,
                                  opt=Opt(
                                      CoAPOptionLocationQuery("first=1"),
                                      CoAPOptionLocationQuery("second=2"),
                                  )))

        if self.match('server', CoAP(pl=Not(b'')), None):
            self.match("server", CoAP(opt=Opt(CoAPOptionContentFormat()), ), "fail")

        self.next_skip_ack(optional=True)
