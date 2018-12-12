from ..common import *


class TD_M2M_NH_40(CoAPTestCase):
    """
TD_M2M_NH_40
    cfg: M2M_CFG_01
    obj: AE retrieves information of a pollingChannel resource via a Retrieve Request.
    pre:
       - AE has created an Application Entity resource <AE> on Registrar CSE
       - AE has created a container resource < pollingChannel > on Registrar CSE
    ref: 'TS-0001 [1], clause 10.2.13.3; TS-0004 [2], clause 7.3.21.2.2'
    seq:
    - s: 
      - 'AE is requested to send a AE GET request to Registrar CSE with'
      - - Type = 0(CON)
        - Code = 1(GET)
        - Uri-Path = {CSEBaseName}/URI of <pollingChannel> resource

    - c: 
      - 'Sent Get request contains'
      - - Type=0 and Code=1
        - Uri-Host = IP address or the FQDN of registrar CSE
        - Uri-Path = {CSEBaseName}/URI of <pollingChannel> resource
        - oneM2M-FR=AE-ID
        - oneM2M-RQI=token-string (->CRQI)
        - Empty payload

    - c: 
        - 'Registrar CSE sends response containing'
        - - Code = 2.05(Content)
          - oneM2M-RSC=2000
          - oneM2M-RQI=CRQI
          - content-format=application/vnd.oneM2M-res+xml or application/vnd.oneM2M-res+json
          - Non-empty Payload

    - v:
        - 'AE indicates successful operation'
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
        self.match('client', CoAP(opt=self.uri('')), 'fail')
        if self.match('client', CoAP(opt=Opt(CoAPOptionOneM2MRequestIdentifier())), 'fail'):
            CMID = self.coap['mid']
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
