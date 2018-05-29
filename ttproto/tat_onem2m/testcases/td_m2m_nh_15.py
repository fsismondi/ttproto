from ..common import *


class TD_M2M_NH_15(CoAPTestCase):
    """
---
TD_M2M_NH_15:
    cfg: M2M_CFG_01
    obj: AE retrieves information of a contentInstance resource via a contentInstance Retrieve Request
    pre: AE has created an Application Entity resource <AE> on registrar CSE,
         AE has created a container resource <container> on Registrar CSE, 
         and AE has created a contentInstance resource <contentInstance> as child resource of <container> resource.
    ref: 'TS-0001, clause 10.2.19.3 ; TS-0004, clause 7.3.6.2.2'
    seq:
    -   s:
        - 'AE is requested to send a GET request for a <contentInstance> with:'
        -   - Type = 0(CON)
            - Code = 1(GET)
    -   c:
        - 'The request sent by AE contains:'
        -   - Type=0 and Code=1
            - oneM2M-RQI=token-string (CRQI)
            - oneM2M-FR=AE-ID
            - Uri-Path option "{CSEBaseName}/URI of <contentInstance> resource"
            - Empty playload
    -   c:
        - 'Registrar CSE sends response containing:'
        -   - Code = 2.05(Content)
            - oneM2M-RQI=CRQI
            - Content-format option
            - Non-empty Payload
            - oneM2M-RSC=2000
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
        
        self.match('client', CoAP(type='con', code='get'), 'fail')
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
