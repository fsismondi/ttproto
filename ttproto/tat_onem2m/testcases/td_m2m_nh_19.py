from ..common import *


class TD_M2M_NH_19(CoAPTestCase):
    """
---
TD_M2M_NH_19:
    cfg: M2M_CFG_01
    obj: AE discovers accessible resources residing in Registrar CSE using the label filter criteria
    pre: CSEBase resource has been created in CSE with name {CSEBaseName} and a <container> resource with label "key1" is created on registrar CSE.
    ref: 'TS-0001, clause 10.2.6 ; TS-0004, clause 7.2.3.13'
    seq:
    -   s:
        - 'AE is requested to send a discovery request in order to discover a <container> resource using the label filter criteria with:'
        -   - Type = 0(CON)
            - Code = 1(GET)
    -   c:
        - 'The request sent by AE contains:'
        -   - Type=0 and Code=1
            - oneM2M-FR option=AE-ID
            - oneM2M-RQI option=token-string (CRQI)
            - UriQuery option="fu=1"
            - UriQuery option="lbl=key1"
            - Empty payload
    -   c:
        - 'Registrar CSE sends response containing:'
        -   - Code = 2.05(Content)
            - oneM2M-RSC option=2000
            - oneM2M-RQI option=CRQI
            - Content-format option
            - Non-empty Payload
    -   v: AE indicates successfull operation
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
        
        self.match('client', CoAP(type='con', code='get', pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionOneM2MFrom())), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionUriQuery('fu=1'))), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionUriQuery('lbl=key1'))), 'fail')
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
