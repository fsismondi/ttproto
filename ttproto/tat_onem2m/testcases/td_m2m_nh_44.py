from ..common import *


class TD_M2M_NH_44(CoAPTestCase):
    """

TD_M2M_NH_44:
    cfg: M2M_CFG_01
    obj: AE creates a <contentInstance> resource in each group member
    pre:
      - A group is created containing 2 members of type <container>
    ref: 'TS-0001 [1], clause 10.2.7.6; TS-0004 [2], clause 7.3.14.3.1'
    seq:
    - s:
      - 'AE is requested to send a Create Request to create <contentInstance> in each group member'
      - - Type = 0 (CON)
        - Code = 2 (POST)
        - Content-format option
        - Non-empty Payload

    - c:
      - 'Sent POST request contains'
      - - Type=0 and Code=2
        - Uri-Host = IP address or the FQDN of registrar CSE
        - Uri-Path = {CSEBaseName}/{group}/fanoutPoint
        - content-type=application/vnd.oneM2M-res+xml or application/vnd.oneM2M-res+json 
        - oneM2M-TY=4
        - oneM2M-FR=AE-ID
        - oneM2M-RQI=token-string (-> CRQI)
        - Non-empty Payload

    - v:
        - 'Check if possible that the <contentInstance> resource is created in each member hosting CSE'

    - c:
        - 'Registrar CSE sends response containing'
        - - Code=2.01(Created)
          - oneM2M-RSC=2001
          - oneM2M-RQI=CRQI
          - Non-empty Payload:aggregated response

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

        .. note::
            Check the number/value of the uri query options or not?
        """
        return [
            CoAP(type='con', code='post')
        ]


    def run (self):
        self.match('client', CoAP (type="con", code="post",pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat())), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionOneM2MFrom())), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionOneM2MTY('4'))), 'fail')

        if self.match('client', CoAP(opt=Opt(CoAPOptionOneM2MRequestIdentifier())), 'fail'):
            CMID = self.coap['mid']
            CTOK = self.coap['tok']
            OPTS = self.coap['opt']
            RI = OPTS[CoAPOptionOneM2MRequestIdentifier]
            RIVAL = RI[2]

            self.next()

            self.match('server', CoAP(code=2.01, mid=CMID, tok=CTOK, pl=Not(b'')), 'fail')
            self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat())), 'fail')
            self.match('server', CoAP(opt=Opt(CoAPOptionOneM2MResponseStatusCode('2001'))), 'fail')
            self.match('server', CoAP(opt=Opt(CoAPOptionOneM2MRequestIdentifier(RIVAL))), 'fail')
            self.match('server', CoAP(opt=Opt(CoAPOptionLocationPath())), 'fail')

