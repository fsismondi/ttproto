from ..common import *


class TD_COAP_CORE_02 (CoAPTestCase):
    """
---
TD_COAP_CORE_02:
    cfg: CoAP_CFG_BASIC
    obj: Perform DELETE transaction (CON mode)
    pre: Server offers a /test resource that handles DELETE
    ref: '[COAP] 5.8.4, 1.2, 2.1, 2.2, 3.1'
    seq:
    -   s:
        - 'Client is requested to send a DELETE request with:'
        -   - Type = 0 (CON)
            - Code = 4 (DELETE)
    -   c:
        - 'The request sent by the client contains:'
        -   - Type=0 and Code=4
            - "Client-generated Message ID (\u2794 CMID)"
            - "Client-generated Token (\u2794 CTOK)"
            - Uri-Path option "test"
    -   c:
        - 'Server sends response containing:'
        -   - Code = 2.02 (Deleted)
            - Message ID = CMID, Token = CTOK
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
        return [CoAP(code='delete')]

    def run(self):
        self.match(
            'client',
            CoAP(type='con', code='delete', opt=self.uri('/test'))
        )
        CMID = self.coap['mid']
        CTOK = self.coap['tok']

        self.next()

        self.match(
            'server',
            CoAP(code=2.02, mid=CMID, tok=CTOK)
        )

        if self.match('server', CoAP(pl=Not(b'')), None):
            self.match(
                'server',
                CoAP(opt=Opt(CoAPOptionContentFormat())),
                'fail'
            )
