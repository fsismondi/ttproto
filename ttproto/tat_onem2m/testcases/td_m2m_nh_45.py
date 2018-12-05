from ..common import *


class TD_M2M_NH_46(CoAPTestCase):
    """
    TD_M2M_NH_47
    cfg: M2M_CFG_01
    obj: AE updates an <container> resource of each member resource.
    pre:
      - A group is created containing 2 members of type <container>
    ref: 'TS-0001 [1], clause 10.2.7.9; TS-0004 [2], clause 7.3.14.3.3'
    seq:
     - s:
      - 'AE is requested to send a Update Request to the fanoutPoint of <group> resource to lifetime of the resource'
      - - Type = 0 (CON)
        - Code = 3 (PUT)
        - Content-format option
        - Non-empty Payload

     - c:
      - 'Sent PUT request contains'
      - - Type=0 and Code=3
        - Uri-Host = IP address or the FQDN of registrar CSE
        - Uri-Path = {CSEBaseName}/{group}/fanoutPoint
        - content-format=application/vnd.oneM2M-res+xml or application/vnd.oneM2M-res+json 
        - oneM2M-FR=AE-ID
        - oneM2M-RQI=token-string (-> CRQI)
        - Non-empty Payload:Serialized representation of <container> resource

    -v:
        - 'Check if possible that both of the <container> resources have been updated in registrar CSE'

    -c:
        - 'Registrar CSE sends response containing'
        - - Code=2.04(changed)
          - oneM2M-RSC=2004
          - oneM2M-RQI=CRQI
          - Content-format=application/vnd.oneM2M-res+xml or application/vnd.oneM2M-res+json
          - Non-empty Payload:aggregated response

    -v:
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
