from ..common import *


class TD_COAP_CORE_12(CoAPTestCase):
    """
---
TD_COAP_CORE_12:
    cfg: CoAP_CFG_BASIC
    not: Not all clients may be able to send a zero-length Token
    obj: Perform GET transaction using empty Token (CON mode)
    pre: Server offers the resource /test with resource content is not empty
        that handles GET with an arbitrary payload
    ref: '[COAP] 2.2, 5.8.1, 5.10.1'
    seq:
    -   s: "Client is requested to send a confirmable GET request using\
            \ zero-length Token to server\u2019s resource "
    -   c:
        - 'The request sent by the client contains:'
        -   - Type = 0 (CON)
            - Code = 1 (GET)
            - "Zero-Length Token \u2794 CTOK"
            - Uri-Path option "test"
    -   c:
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
        return [
            CoAP(type='con', code='get', tok=b'', opt=Opt(CoAPOptionUriPath("test")))
        ]

    def run(self):
        self.match("client", CoAP(type="con", code="get", tok=b"", opt=self.uri("/test")))

        self.next_skip_ack()

        if self.match("server", CoAP(code=2.05, pl=Not(b""), opt=Opt(CoAPOptionContentFormat()), )):
            self.match("server", CoAP(tok=b""), "fail")
