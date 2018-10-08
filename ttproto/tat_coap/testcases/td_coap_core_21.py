from ..common import *
import logging


class TD_COAP_CORE_21(CoAPTestCase):
    """
---
TD_COAP_CORE_21:
    cfg: CoAP_CFG_BASIC
    obj: Perform GET transaction containing the ETag option (CON mode)
    pre:
        - Server should offer a /validate resource which may be made to vary
            over time
        - Client & server supports ETag option
        - "The Client\u2019s cache must be purged"
    ref: '[COAP] 5.8.1, 5.10.7, 5.10.10, 12.1.12'
    seq:
        -   n: Verifying that client cache is empty
        -   s: "Client is requested to send a confirmable GET request to server\
                \u2019s resource"
        -   c:
            - 'The request sent request by the client contains:'
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
                  (\u2794 ETAG1)"
                - Non-empty Payload
        -   v: 'Client displays the response '
        -   n: Verifying client cache entry is still valid
        -   s: "Client is requested to send a confirmable GET request to server\
                \u2019s resource so as to check if the resource was updated"
        -   c:
            - 'The request sent by the client contains:'
            -   - Type = 0 (CON)
                - Code = 1 (GET)
                - "Another client-generated Message ID \u2260 CMID (\u2794 CMID2)"
                - "Client-generated Token which may or may not be \u2260 CTOK\
                   (\u2794 CTOK2)"
                - Uri-Path option "validate"
                - Option Type = ETag, value = ETAG1 (the ETag value received
                    in step 3)
        -   c:
            - 'Server sends response containing:'
            -   - Code = 2.03 (Valid)
                - Message ID = CMID2, Token = CTOK2
                - Option type = ETag, value = ETAG1
                - Empty Payload
        -   v: 'Client displays the response '
        -   n: Verifying that client cache entry is no longer valid
        -   s: "Update the content of the server\u2019s resource from a CoAP\
                client (either another client, or the testing client in a\
                separate transaction)"
        -   s: "Client is requested to send a confirmable GET request to server\
                \u2019s resource so as to check if the resource was updated"
        -   c:
            - 'The request sent by the client contains:'
            -   - Type = 0 (CON)
                - Code = 1 (GET)
                - "Another client-generated Message ID \u2260 CMID and \u2260\
                   CMID2 (\u2794 CMID3)"
                - "Client-generated Token which may or may not be \u2260 CTOK\
                   or CTOK2 (\u2794 CTOK3)"
                - Uri-Path option "validate"
                - Option Type = ETag, value = ETAG1 (the ETag value received
                    in step 3)
        -   c:
            - 'Server sends response containing:'
            -   - Code = 2.05 (Content)
                - Message ID = CMID3, Token = CTOK3
                - "Option type = ETag, value = another ETag value \u2260 ETAG1"
                - The payload of the requested resource, which should be different
                    from the payload in step 3
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
            CoAP(type='con', code='get', opt=Opt(CoAPOptionUriPath("validate"))),  # Step 1
            CoAP(type='con', code='get', opt=Opt(CoAPOptionUriPath("validate"))),  # Step 5
            CoAP(type='con', code='put', opt=Opt(CoAPOptionUriPath("validate"))),  # Step 9
            CoAP(type='con', code='get', opt=Opt(CoAPOptionUriPath("validate")))  # Step 10
        ]

    def run(self):
        # Part A
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
        pl3 = self.coap["pl"]

        self.next_skip_ack(optional=True)

        # Part B
        # Step 6
        self.match("client", CoAP(type="con",
                                  code="get",
                                  opt=Opt(
                                      CoAPOptionUriPath("validate"),
                                      CoAPOptionETag(ETAG1),
                                  )))
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
                                  code=2.03,
                                  mid=CMID2,
                                  tok=CTOK2,
                                  opt=Opt(CoAPOptionETag(ETAG1)),
                                  pl=b""))

        self.next_skip_ack(optional=True)

        # Part C

        if self.match("client", CoAP(code="put"), None):
            # allow an update from another client running on the same host
            self.next_skip_ack()
            self.match("server", CoAP(code=2.04))
            self.next_skip_ack(optional=True)
        # Step 11
        self.match("client", CoAP(type="con",
                                  code="get",
                                  opt=Opt(
                                      CoAPOptionUriPath("validate"),
                                      CoAPOptionETag(ETAG1),
                                  )))
        CMID3 = self.coap["mid"]
        CTOK3 = self.coap["tok"]

        if CMID3 != b"":
            if CMID3 == CMID or CMID3 == CMID2:
                self.set_verdict("fail", "Message ID should be different")
        if CTOK3 != b"":
            if CTOK3 == CTOK or CTOK3 == CTOK2:
                self.set_verdict("fail", "Token should be different")

        self.next_skip_ack()
        # Step 12
        self.match("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                  code=2.05,
                                  mid=CMID3,
                                  tok=CTOK3,
                                  opt=Opt(CoAPOptionETag(Not(ETAG1))),
                                  pl=All(Not(b""), Not(pl3))), 'fail')

        self.next_skip_ack(optional=True)
