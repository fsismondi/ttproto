from ..common import *


class TD_COAP_CORE_20(CoAPTestCase):
    """
---
TD_COAP_CORE_20:
    cfg: CoAP_CFG_BASIC
    obj: Perform GET transaction containing the Accept option (CON mode)
    pre:
        - 'Server should provide a resource /multi-format which exists in two
            formats: '
        -   - text/plain;charset=utf-8
            - application/xml
    ref: '[COAP] 5.8.1, 5.10.5, 5.10.4'
    seq:
        -   n: client requests a resource in text format
        -   s: "Client is requested to send a confirmable GET request to server\
                \u2019s resource"
        -   c:
            - 'The request sent request by the client contains:'
            -   - Type = 0 (CON)
                - Code = 1 (GET)
                - "Client-generated Message ID (\u2794 CMID)"
                - "Client-generated Token (\u2794 CTOK)"
                - Option type = Accept, value = 0 (text/plain;charset=utf-8)
                - Uri-Path option "multi-format"
        -   c:
            - 'Server sends response containing:'
            -   - Code = 2.05 (Content)
                - Message ID = CMID, Token = CTOK
                - Option type = Content-Format, value = 0
                                (text/plain;charset=utf-8)
                - Payload = Content of the requested resource in
                            text/plain;charset=utf-8 format
        -   v: Client displays the response
        -   n: client requests a resource in xml format
        -   s: "Client is requested to send a confirmable GET request to server\
                \u2019s resource"
        -   c:
            - 'The request sent by the client contains:'
            -   - Type = 0 (CON)
                - Code = 1 (GET)
                - "Another client-generated Message ID \u2260 CMID (\u2794 CMID2)"
                - "Client-generated Token which may or may not be \u2260 CTOK\
                    \ (\u2794 CTOK2)"
                - Option type = Accept, value = 41 (application/xml)
        -   c:
            - 'Server sends response containing:'
            -   - Code = 2.05 (Content)
                - Message ID = CMID2, Token = CTOK2
                - Option type = Content-Format, value = 41 (application/xml)
            - Payload = Content of the requested resource in application/xml
                format
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
            # Step 1 and Step 5 are the same stimulis.
            CoAP(type='con', code='get', opt=Opt(CoAPOptionUriPath("multi-format")))
        ]

    def run(self):

        # Step 2
        self.match("client", CoAP(type="con",
                                  code="get",
                                  opt=self.uri("/multi-format") if self.urifilter else Opt(CoAPOptionAccept())))

        self.match("client", CoAP(type="con",
                                  code="get",
                                  opt=Opt(CoAPOptionAccept(0))))
        CMID = self.coap["mid"]
        CTOK = self.coap["tok"]

        self.next_skip_ack()
        # Step 3
        self.match("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                  code=2.05,
                                  mid=CMID,
                                  tok=CTOK,
                                  opt=Opt(CoAPOptionContentFormat(0)),
                                  pl=Not(b"")))

        self.next_skip_ack(optional=True)
        # Step 6
        self.match("client", CoAP(type="con",
                                  code="get",
                                  opt=self.uri("/multi-format", CoAPOptionAccept(41))))
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
        self.match("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                  code=2.05,
                                  mid=CMID2,
                                  tok=CTOK2))

        if self.match("server", CoAP(pl=Not(b""))):
            self.match("server", CoAP(opt=Opt(CoAPOptionContentFormat(41)),), "fail")

        self.next_skip_ack(optional=True)
