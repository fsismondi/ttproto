from ..common import *


class TD_COAP_CORE_11(CoAPTestCase):
    """
---
TD_COAP_CORE_11:
    cfg: CoAP_CFG_BASIC
    obj: Perform GET transaction containing non-empty Token with a separate
        response (CON mode)
    pre: Server offers a resource /separate which is not served immediately
        and which therefore is not acknowledged in a piggybacked way.
    ref: '[COAP] 2.2, 5.2.2, 5.8.1'
    seq:
    -   s: "Client is requested to send a GET request to server\u2019s resource\
            \ including Token option"
    -   c:
        - 'The request sent by the client contains:'
        -   - Type = 0 (CON)
            - Code = 1 (GET)
            - "Client-generated Message ID (\u2794 CMID)"
            - "Client-generated Token (\u2794 CTOK)"
            - Length of the token should be between 1 to 8 Bytes
            - Uri-Path option "separate"
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
        # TODO client message w/ token length = 0 -> fail?
        return [
            CoAP(type='con', code='get', tok=Not(b''), opt=Opt(CoAPOptionUriPath("separate")))
        ]

    def run(self):
        self.match("client", CoAP(type="con", code="get", tok=Not(b""), opt=self.uri("/separate"), ))
        self.match("client", CoAP(tok=Length(bytes, (1, 8))), "fail")
        CMID = self.coap["mid"]
        CTOK = self.coap["tok"]

        self.next()
        # FIXME: may be out-of-order
        if not self.match("server", CoAP(type="ack", code=0, mid=CMID, pl=b"")):
            raise self.Stop()

        self.next()
        # FIXME: this is in a different conversation
        self.match("server", CoAP(type="con", code=2.05))
        self.match("server", CoAP(pl=Not(b''), tok=CTOK, ), "fail")
        SMID = self.coap["mid"]

        self.next()
        self.match("client", CoAP(type="ack", code=0, mid=SMID, pl=b""))
