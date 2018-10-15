from ..common import *


class TD_COAP_CORE_03(CoAPTestCase):
    """
---
TD_COAP_CORE_03:
    cfg: CoAP_CFG_BASIC
    obj: Perform PUT transaction (CON mode)
    pre: Server offers already available resource /test or accepts creation
        of new resource on /test that handles PUT
    ref: '[COAP] 5.8.3, 1.2, 2.1, 2.2, 3.1'
    seq:
    -   s:
        - 'Client is requested to send a PUT request with:'
        -   - Type = 0 (CON)
            - Code = 3 (PUT)
            - Content-format option
            - Empty or non-empty Payload
    -   c:
        - 'The request sent by the client contains:'
        -   - Type=0 and Code=3
            - "Client-generated Message ID (\u2794 CMID)"
            - "Client-generated Token (\u2794 CTOK)"
            - Uri-Path option "test"
    -   v: Server displays received information
    -   c:
        - 'Server sends response containing:'
        -   - Code = 2.04 (Changed) or 2.01 (Created)
            - Message ID = CMID, Token = CTOK
            - Content-format option if payload non-empty
            - Empty or non-empty Payload
    -   v: Client displays the received response
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
            CoAP(type='con', code='put', opt=Opt(CoAPOptionUriPath("test")))
        ]

    def run(self):
        self.match("client",
                   CoAP(type="con", code="put", opt=self.uri("/test")))

        self.match("client",
                   CoAP(opt=Opt(CoAPOptionContentFormat()), ),
                   "fail")

        CMID = self.coap["mid"]
        CTOK = self.coap["tok"]

        self.next()

        self.match("server", CoAP(code=Any(65, 68), mid=CMID, tok=CTOK, ))

        if self.match('server', CoAP(pl=Not(b'')), None):
            self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat())), 'fail')
