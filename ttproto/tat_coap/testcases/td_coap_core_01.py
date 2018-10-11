from ..common import *


class TD_COAP_CORE_01(CoAPTestCase):
    """
---
TD_COAP_CORE_01:
    cfg: CoAP_CFG_BASIC
    obj: Perform GET transaction(CON mode)
    pre: Server offers the resource /test with resource content
        is not empty that handles GET with an arbitrary payload
    ref: '[COAP] 5.8.1, 1.2, 2.1, 2.2, 3.1'
    seq:
    -   s:
        - 'Client is requested to send a GET request with:'
        -   - Type = 0(CON)
            - Code = 1(GET)
    -   c:
        - 'The request sent by the client contains:'
        -   - Type=0 and Code=1
            - "Client-generated Message ID(\u2794 CMID)"
            - "Client-generated Token(\u2794 CTOK)"
            - Uri-Path option "test"
    -   c:
        - 'Server sends response containing:'
        -   - Code = 2.05(Content)
            - Message ID = CMID, Token = CTOK
            - Content-format option
            - Non-empty Payload
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
        return [CoAP(type='con', code='get', opt=Opt(CoAPOptionUriPath("test")))]

    def run(self):
        self.match('client', CoAP(type='con', code='get', opt=self.uri('/test')))
        CMID = self.coap['mid']
        CTOK = self.coap['tok']

        self.next()

        self.match('server', template=CoAP(code=2.05, mid=CMID, tok=CTOK))
        if self.match('server',
                   template=CoAP(pl=Not(b'')),
                   on_mismatch_verdict='inconclusive',
                   on_mismatch_msg = 'Test pre-conditions not met by server. Payload should not be empty'
                   ):
            self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat())), 'fail')
