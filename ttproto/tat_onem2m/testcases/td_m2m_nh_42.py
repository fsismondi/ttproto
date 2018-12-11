from ..common import *


class TD_M2M_NH_42 (CoAPTestCase):
    """

    TD_M2M_NH_42
    cfg: M2M_CFG_01
    obj: AE deletes a pollingChannel resource via a Delete Request.
    pre:
      - AE has created an Application Entity resource <AE> on Registrar CSE.
      - AE has created a container resource <container> on Registrar CSE.
   ref: 'TS-0001 [1], clause 10.2.13.5; TS-0004 [2], clause 7.3.21.2.4'
   seq:
    - s:
      - 'AE is requested to send a DELETE request with'
      - - Type = 0(CON)
        - Code = 4(Delete)

    -c:
      - 'Sent Delete request contains'
      - - Type=0 and Code=4
        - Uri-Host= IP address or the FQDN of registrar CSE
        - Uri-Path={CSEBaseName}/URI of <pollingChannel> resource
        - oneM2M-FR=AE-ID
        - oneM2M-RQI=token-string (->CRQI)
        - Empty Payload
       
    -v:
        - 'Check if possible that the < pollingChannel > resource is deleted from Registrar CSE'

    -c:
        - 'Registrar CSE sends response containing'
        - - Code = 2.02(Deleted)
          - oneM2M-RSC=2002
          - oneM2M-RQI=CRQI
          - Empty Payload

   - v:
        - 'Check if possible that the <pollingChannel> resource is deleted in registrar CSE'

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
        return [CoAP(type='con', code='delete')]

    def run(self):
        
        self.match('client', CoAP(type='con', code='delete', pl=(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionOneM2MFrom())), 'fail')
        if self.match('client', CoAP(opt=Opt(CoAPOptionOneM2MRequestIdentifier())), 'fail'):
            CMID = self.coap['mid']
            CTOK = self.coap['tok']
            OPTS = self.coap['opt']
            RI = OPTS[CoAPOptionOneM2MRequestIdentifier]
            RIVAL = RI[2]

            self.next()

            self.match('server', CoAP(code=2.02, mid=CMID, tok=CTOK, pl=(b'')), 'fail')
            self.match('server', CoAP(opt=Opt(CoAPOptionOneM2MResponseStatusCode('2002'))), 'fail')
            self.match('server', CoAP(opt=Opt(CoAPOptionOneM2MRequestIdentifier(RIVAL))), 'fail')
