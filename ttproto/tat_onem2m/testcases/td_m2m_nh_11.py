from ..common import *


class TD_M2M_NH_11(CoAPTestCase):
    """

TD_M2M_NH_11:
    cfg: M2M_CFG_01
    obj: AE retrieves information of a <container> resource via a container Retieve Request
    pre: AE has created an Application Entity resource <AE> on Registrar CSE
         and AE has created a container resource <container> on Registrar CSE.
    ref: 'TS-0001, clause 10.2.4.2 ; TS-0004, clause 7.3.5.2.2'
    seq:
    -   s:
        - 'AE is requested to send a GET request for a <container> with:'
        -   - Type = 0(CON)
            - Code = 1(GET)
    -  c:
        - 'The request sent by AE contains:'
        -   - Type=0 and Code=1
            - oneM2M-RQI option=token-string (CRQI)
            - oneM2M-FR option=AE-ID
            - Empty playload
    -   c:
        - 'Registrar CSE sends response containing:'
        -   - Code = 2.05(Content)
            - oneM2M-RQI option=CRQI
            - oneM2M-RSC option=2000
            - Content-format option
            - Non-empty Payload
    -   v: AE displays the received information
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
        return [CoAP(type='con', code='get')]

    def run(self):
        
        self.match('client', CoAP(type='con', code='get', pl=(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionOneM2MFrom())), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionUriPath())), 'fail')
        if self.match('client', CoAP(opt=Opt(CoAPOptionOneM2MRequestIdentifier())), 'fail'):
            CMID = self.coap['mid']
            CTOK = self.coap['tok']
            OPTS = self.coap['opt']
            RI = OPTS[CoAPOptionOneM2MRequestIdentifier]
            RIVAL = RI[2]

            self.next()

            self.match('server', CoAP(code=2.05, mid=CMID, tok=CTOK, pl=Not(b'')), 'fail')
            self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat())), 'fail')
            self.match('server', CoAP(opt=Opt(CoAPOptionOneM2MResponseStatusCode('2000'))), 'fail')
            self.match('server', CoAP(opt=Opt(CoAPOptionOneM2MRequestIdentifier(RIVAL))), 'fail')
