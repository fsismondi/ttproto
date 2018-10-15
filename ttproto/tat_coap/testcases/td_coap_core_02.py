from ..common import *


class TD_COAP_CORE_02(CoAPTestCase):
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
        return [CoAP(type='con', code='delete', opt=Opt(CoAPOptionUriPath("test")))]

    def run(self):

        verdict_if_none = "inconclusive"

        while self.match('client', CoAP(type='con', code='delete', opt=self.uri('/test')), verdict_if_none):
            CMID = self.coap['mid']
            CTOK = self.coap['tok']

            self.next()

            if self.match('server', CoAP(code=2.02, mid=CMID, tok=CTOK)):
                pass  # Pass cases, nothing to do.
            elif self.match('server', CoAP(mid=CMID, tok=CTOK), None):
                code = self.coap['code']
                # Fail cases : when code is 2.01/2.03/2.04/2.05
                if code == 65 or code == 67 or code == 68 or code == 69:
                    self.set_verdict("fail", "Server responded to a deletion request with " + str(code))
                else:  # Inconclusive cases.
                    # Other code 4.xx/5.xx, e.g various errors.
                    # We cannot trow a Fail verdict here because even if it do
                    # not correspond to a check step, it does not violate the RFC
                    # either.
                    self.set_verdict("inconclusive", "Server responded to a deletion request with " + str(code))

            if self.match('server', CoAP(pl=Not(b'')), None):
                self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat())), 'fail')

            verdict_if_none = None
            self.next(True)
