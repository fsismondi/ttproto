#!/usr/bin/env python3

from ..common import *


class TD_COAP_CORE_22(CoAPTestCase):
    """
---
TD_COAP_CORE_22:
    cfg: CoAP_CFG_BASIC
    obj: Perform GET transaction with responses containing the ETag option
        and requests containing the If-Match option (CON mode)
    pre:
    - Server offers a /validate resource
    - Client & server supports ETag and If-Match option
    - "The Client \u2018s cache must be purged"
    ref: '[COAP] 5.8.1, 5.10.7, 5.10.9, 12.1.12'
    seq:
    -   n: client gets the resource
    -   s: "Client is requested to send a confirmable GET request to server\
            \u2019s resource"
    -   c:
        - 'The request sent by the client contains:'
        -   - Type = 0 (CON)
            - Code = 1 (GET)
            - "Client-generated Message ID (\u2794 CMID)"
            - "Client-generated Token (\u2794 CTOK)"
            - Uri-Path option "validate"
            - No ETag option
    -   c:
        - 'Server sends response containing:'
        -   - Code = 2.05 (Content)
            - Message ID = CMID, Token = CTOK
            - "Option type = ETag, value = a value chosen by the server\
                \ (\u2794 ETAG1)"
            - Non-empty Payload
    -   n: single update
    -   s: "Client is requested to send a confirmable PUT request to server\
            \u2019s resource so as to perform an atomic update"
    -   c:
        - 'The request sent by the client contains:'
        -   - Type = 0 (CON)
            - Code = 3 (PUT)
            - "Another client-generated Message ID \u2260 CMID (\u2794 CMID2)"
            - "Client-generated Token which may or may not be \u2260 CTOK\
                \ (\u2794 CTOK2)"
            - Content-format option
            - Uri-Path option "validate"
            - Option type = If-Match, value = ETAG1 (ETag value received
                in step 3)
            - An arbitrary payload (which differs from the payload received
                in step 3)
    -   c:
        - 'Server sends response containing:'
        -   - Code = 2.04 (Changed)
            - Message ID = CMID2, Token = CTOK2
            - Content-format option if payload non-empty
            - Empty or non-empty Payload
    -   v: 'Client displays the response and the server changed its resource '
    -   n: concurrent updates
    -   s: "Client is requested to send a confirmable GET request to server\
            \u2019s resource"
    -   c:
        - 'The request sent by the client contains:'
        -   - Type = 0 (CON)
            - Code = 1 (GET)
            - "Another client-generated Message ID \u2260 CMID and \u2260\
                \ CMID2 (\u2794 CMID3)"
            - "Client-generated Token which may or may not be \u2260 CTOK\
                \ or CTOK2 (\u2794 CTOK3)"
            - Uri-Path option "validate"
    -   c:
        - 'Server sends response containing:'
        -   - Code = 2.05 (Content)
            - Message ID = CMID3, Token = CTOK3
            - "Option type = ETag, value = a value \u2260 ETAG1 chosen by\
                \ the server (\u2794 ETAG2)"
            - The Payload sent in step 5
    -   v: 'Client displays the response '
    -   s: "Update the content of the server\u2019s resource from a CoAP\
            \ client once more"
    -   c:
        - 'The request sent by the client contains:'
        -   - Type = 0 (CON)
            - Code = 3 (PUT)
            - "Another client-generated Message ID \u2260 CMID, CMID2, CMID3\
                \ (\u2794 CMID4)"
            - "Client-generated Token which may or may not be \u2260 CTOK,\
                \ CTOK2, CTOK3 (\u2794 CTOK4)"
            - Content-format option
            - Uri-Path option "validate"
            - An arbitrary payload (which differs from the payloads received
                in steps 3 and 10)
    -   c:
        - 'Server sends response containing:'
        -   - Code = 2.04 (Changed)
            - Message ID = CMID4, Token = CTOK4
            - Content-format option if payload non-empty
            - Empty or non-empty Payload
    -   v: 'Client displays the response and the server changed its resource '
    -   s: "Client is requested to send a confirmable PUT request to server\
            \u2019s resource so as to perform an atomic update, assuming it is\
            \ still unchanged from step 10"
    -   c:
        - 'The request sent by the client contains:'
        -   - Type = 0 (CON)
            - Code = 3 (PUT)
            - "Another client-generated Message ID \u2260 CMID, CMID2, CMID3\
                \ (\u2794 CMID4)"
            - "Client-generated Token which may or may not be \u2260 CTOK,\
                \ CTOK2, CTOK3 (\u2794 CTOK4)"
            - Content-format option
            - Uri-Path option "validate"
            - Option type = If-Match, value = ETAG2 (ETag value received
                in step 10)
            - An arbitrary payload (which differs from the previous payloads)
    -   c:
        - 'Server sends response containing:'
        -   - Code = 4.12 (Precondition Failed)
            - Message ID = CMID4, Token = CTOK4
            - Optional Content-format option
            - Empty or non-empty Payload
    -   v: Client displays the response and the server did not update the
            content of the resource
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
            CoAP(type='con', code='get', opt=Opt(CoAPOptionUriPath("validate"))),  # Step 1
            CoAP(type='con', code='put', opt=Opt(CoAPOptionUriPath("validate"))),  # Step 4
            CoAP(type='con', code='get', opt=Opt(CoAPOptionUriPath("validate"))),  # Step 8
            CoAP(type='con', code='put', opt=Opt(CoAPOptionUriPath("validate"))),  # Step 12
            CoAP(type='con', code='put', opt=Opt(CoAPOptionUriPath("validate")))  # Step 13
        ]

    def run(self):
        # Preamble
        # Step 2
        self.match("client", CoAP(type="con",
                                  code="get",
                                  opt=All(
                                      Opt(CoAPOptionUriPath("validate")),
                                      NoOpt(CoAPOptionETag()),
                                  )))
        CMID = self.coap["mid"]
        CTOK = self.coap["tok"]

        self.next_skip_ack()

        # Step 3
        if not self.match("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                         code=2.05,
                                         mid=CMID,
                                         tok=CTOK,
                                         opt=Opt(CoAPOptionETag()),
                                         pl=Not(b""))):
            raise self.Stop()

        ETAG1 = self.coap["opt"][CoAPOptionETag]["val"]
        pl_3 = self.coap["pl"]

        self.next_skip_ack(optional=True)

        # Part A

        # Step 5

        self.match("client", CoAP(type="con",
                                  code="put",
                                  opt=Opt(
                                      CoAPOptionContentFormat(),
                                      CoAPOptionUriPath("validate"),
                                      CoAPOptionIfMatch(ETAG1),
                                  ),
                                  pl=All(Not(b""), Not(pl_3))))
        CMID2 = self.coap["mid"]
        CTOK2 = self.coap["tok"]

        if CMID2 != b"":
            if CMID2 == CMID:
                self.set_verdict("fail", "Message ID should be different")
        if CTOK2 != b"":
            if CTOK2 == CTOK:
                self.set_verdict("fail", "Token should be different")
        pl_5 = self.coap["pl"]
        self.next_skip_ack()

        # Step 6
        if not self.match("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                         code=2.04,
                                         mid=CMID2,
                                         tok=CTOK2)):
            raise self.Stop()
        if self.match("server", CoAP(pl=Not(b"")), None):
            self.match("server", CoAP(
                opt=Opt(CoAPOptionContentFormat()),
            ), "fail")

        self.next_skip_ack(optional=True)

        # Part B

        # Step 9

        self.match("client", CoAP(type="con",
                                  code="get",
                                  opt=Opt(CoAPOptionUriPath("validate"))))
        CMID3 = self.coap["mid"]
        CTOK3 = self.coap["tok"]

        if CMID3 != b"":
            if CMID3 == CMID or CMID3 == CMID2:
                self.set_verdict("fail", "Message ID should be different")
        if CTOK3 != b"":
            if CTOK3 == CTOK or CTOK3 == CTOK2:
                self.set_verdict("fail", "Token should be different")

        self.next_skip_ack()

        # Step 10
        if not self.match("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                         code=2.05,
                                         mid=CMID3,
                                         tok=CTOK3,
                                         opt=Opt(CoAPOptionETag(Not(ETAG1))),
                                         pl=pl_5)):
            raise self.Stop()

        ETAG2 = self.coap["opt"][CoAPOptionETag]["val"]
        pl_10 = self.coap["pl"]

        self.next_skip_ack(optional=True)

        # Step 13
        self.match("client", CoAP(type="con",
                                  code="put",
                                  opt=Opt(
                                      CoAPOptionUriPath("validate"),
                                      CoAPOptionContentFormat(),
                                  ),
                                  pl=All(Not(b""), Not(pl_3), Not(pl_10))))
        CMID_step13 = self.coap["mid"]
        CTOK_step13 = self.coap["tok"]

        if CMID_step13 != b"":
            if CMID_step13 == CMID or CMID_step13 == CMID2 or CMID_step13 == CMID3:
                self.set_verdict("fail", "Message ID should be different")
        if CTOK_step13 != b"":
            if CTOK_step13 == CTOK or CTOK_step13 == CTOK2 or CTOK_step13 == CTOK3:
                self.set_verdict("fail", "Token should be different")
        pl_13 = self.coap["pl"]

        self.next_skip_ack()

        # Step 13 bis
        self.match("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                  code=2.04,
                                  mid=CMID_step13,
                                  tok=CTOK_step13, ))

        if self.match("server", CoAP(pl=Not(b"")), None):
            self.match("server", CoAP(opt=Opt(CoAPOptionContentFormat()), ), "fail")

        self.next_skip_ack(optional=True)

        # Step 14

        self.match("client", CoAP(type="con",
                                  code="put",
                                  opt=Opt(
                                      CoAPOptionContentFormat(),
                                      CoAPOptionUriPath("validate"),
                                      CoAPOptionIfMatch(ETAG2),
                                  ),
                                  pl=All(Not(b""), Not(pl_13))))
        CMID4 = self.coap["mid"]
        CTOK4 = self.coap["tok"]

        if CMID4 != b"":
            if CMID4 == CMID or CMID4 == CMID2 or CMID4 == CMID3 or CMID4 == CMID_step13:
                self.set_verdict("fail", "Message ID should be different")
        if CTOK4 != b"":
            if CTOK4 == CTOK or CTOK4 == CTOK2 or CTOK4 == CTOK3 or CTOK4 == CTOK_step13:
                self.set_verdict("fail", "Token should be different")

        self.next_skip_ack()
        # Step 15
        self.match("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                  code=4.12,
                                  mid=CMID4,
                                  tok=CTOK4), 'fail')
