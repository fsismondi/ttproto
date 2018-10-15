from ..common import *


class TD_COAP_CORE_06(CoAPTestCase):
    """
---
TD_COAP_CORE_06:
    cfg: CoAP_CFG_BASIC
    obj: Perform DELETE transaction (NON mode)
    pre: Server offers a /test resource that handles DELETE
    ref: '[COAP] 5.8.4, 5.2.3'
    seq:
    -   s:
        - 'Client is requested to send a DELETE request with:'
        -   - Type = 1 (NON)
            - Code = 4 (DELETE)
    -   c:
        - 'The request sent by the client contains:'
        -   - Type=1 and Code=4
            - "Client-generated Message ID (\u2794 CMID)"
            - "Client-generated Token (\u2794 CTOK)"
            - Uri-Path option "test"
    -   c:
        - 'Server sends response containing:'
        -   - Type = 1 (NON)
            - Code = 2.02 (Deleted)
            - "Server-generated Message ID (\u2794 SMID)"
            - Token = CTOK
            - Content-format option if payload non-empty
            - Empty or non-empty Payload
    -   v: Client displays the received information
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
        return [CoAP(type='non', code='delete',opt=Opt(CoAPOptionUriPath("test")))]

    def run(self):
        self.match("client", CoAP(type="non", code="delete",opt=self.uri("/test")))

        CTOK = self.coap["tok"]

        self.next()

        self.match("server", CoAP(type="non", code=2.02, tok=CTOK))

        if self.match("server", CoAP(pl=Not(b"")), None):
            self.match("server", CoAP(opt=Opt(CoAPOptionContentFormat()), ), "fail")
