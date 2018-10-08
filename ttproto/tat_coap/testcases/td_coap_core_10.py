from ..common import *


class TD_COAP_CORE_10(CoAPTestCase):
    """
---
TD_COAP_CORE_10:
    cfg: CoAP_CFG_BASIC
    obj: Perform GET transaction containing non-empty Token (CON mode)
    pre: Server offers a /test resource with resource content is not empty
        that handles GET
    ref: '[COAP] 2.2, 5.8.1, 5.10.1'
    seq:
    -   s: "Client is requested to send a GET request to server\u2019s resource
            \ with non-empty Token option"
    -   c:
        - 'The request sent by the client contains:'
        -   - Type = 0 (CON)
            - Code = 1 (GET)
            - "Client-generated Message ID (\u2794 CMID)"
            - "Client-generated Token (\u2794 CTOK)"
            - Length of the token should be between 1 to 8 Bytes
            - Uri-Path option "test"
    - &id003
        c:
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
        """
        # TODO client message w/ token length = 0 -> fail?
        return [
            CoAP(type='con', code='get', tok=Not(b''),
                 opt=Opt(CoAPOptionUriPath("test")))
        ]

    def run(self):
        self.match("client", CoAP(code="get", type="con", tok=Not(b""), opt=self.uri("/test")))
        self.match("client", CoAP(tok=Length(bytes, (1, 8))), "fail")
        CMID = self.coap["mid"]
        CTOK = self.coap["tok"]

        self.next()

        if self.match("server", CoAP(code=2.05, pl=Not(b""))):
            self.match("server", CoAP(mid=CMID, tok=CTOK, opt=Opt(CoAPOptionContentFormat())), "fail")
