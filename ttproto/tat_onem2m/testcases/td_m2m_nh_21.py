from ..common import *


class TD_M2M_NH_21(CoAPTestCase):
    """
---
TD_M2M_NH_21:
    cfg: M2M_CFG_01
    obj: AE discovers accessible resources residing in Registrar CSE using multiple Filter Criteria .
    pre: Two <Container> resources with labels "key1" and "key2" are created in Registrar CSE and A <Group> resources with labels "key1" and "key2" is created in Registrar CSE.
    ref: 'TS-0001, clause 10.2.6 ; TS-0004, clause 7.2.3.13'
    seq:
    -   s:
        - 'AE is requested to send a Discovery request in order to discover specific resources located in Registrar CSE using multiple filter criteria (label, resource type and limit) with:'
        -   - Type = 0(CON)
            - Code = 1(GET)
    -   c:
        - 'The request sent by AE contains:'
        -   - Type=0 and Code=1
            - oneM2M-FR option=AE-ID
            - oneM2M-RQI option=token-string (CRQI)
            - UriQuery option="fu=1"
            - UriQuery option="lbl=key1"
            - UriQuery option="lbl=key2"
            - UriQuery option="rty=3"
            - UriQuery option="lim=1"
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
        self.match('client', CoAP(opt=Opt(CoAPOptionUriQuery('lbl=key2'))), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionUriQuery('rty=3'))), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionUriQuery('lim=1'))), 'fail')
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
