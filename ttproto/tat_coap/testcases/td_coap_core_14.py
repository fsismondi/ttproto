#!/usr/bin/env python3
from ..common import *


class TD_COAP_CORE_14(CoAPTestCase):
    """
---
TD_COAP_CORE_14:
    cfg: CoAP_CFG_BASIC
    obj: Perform GET transaction containing several URI-Query options(CON mode)
    pre: "Server offers a /query resource with resource content is not empty"
    ref: '[COAP] 5.4.5, 5.10.2, 6.5'
    seq:
    -   s: "Client is requested to send a confirmable GET request with three\
            Query parameters (e.g. ?first=1&second=2&third=3) to the server\
            \u2019s resource"
    -   c:
        - 'The request sent by the client contains:'
        -   - Type = 0 (CON)
            - Code = 1 (GET)
            - "Client-generated Message ID (\u2794 CMID)"
            - "Client-generated Token (\u2794 CTOK)"
            - Uri-Path option "query"
        - 'and two options of Uri-Query, with values such as:'
        -   - first=1
            - second=2
    - c:
        - 'Server sends response containing:'
        -   - Code = 2.05 (Content)
            - Message ID = CMID, Token = CTOK
            - Content-format option
            - Non-empty Payload
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
            CoAP(
                type='con',
                code='get',
                opt=Opt(CoAPOptionUriQuery(),
                        CoAPOptionUriQuery(),
                        CoAPOptionUriPath("query"),
                        superset=True,
                        )
            )
        ]

    def run(self):
        if self.urifilter:
            uri_query_opt = self.uri("/query?first=1&second=2")
        else:
            uri_query_opt = Opt(CoAPOptionUriQuery(), superset=True)

        self.match("client", CoAP(code="get", type="con", opt=uri_query_opt))
        CMID = self.coap["mid"]
        CTOK = self.coap["tok"]

        opts = list(filter((lambda o: isinstance(o, CoAPOptionUriQuery)), self.coap["opt"]))

        if len(opts) < 2:
            self.set_verdict("inconclusive", "expect multiple UriQuery options")

        self.next_skip_ack()

        if self.match('server', CoAP(code=2.05, mid=CMID, tok=CTOK, pl=Not(b''))):
            self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat())), 'fail')
