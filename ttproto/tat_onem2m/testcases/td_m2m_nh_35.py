from ..common import *


class TD_M2M_NH_35(CoAPTestCase):
    """
---
TD_M2M_NH_35:
    cfg: M2M_CFG_01
    obj: AE creates a node resource.
    ref: 'TS-0001, clause 10.2.14.1; TS-0004, clause 7.3.18.2.1'
    seq:
    -   s: "AE is requested to send a POST request to CSE"
    -   c:
        - 'The request sent by AE contains:'
        -   - Type = 0 (CON
            - Code = 2 (POST)
            - An arbitrary payload
            - Content-format option
            - oneM2M-TY "14"
            - oneM2M-FR (originator) "AE_ID"
            - oneM2M-RQI "token-string" (CRQI)
    -   v: Check if possible that the <node> resource is created in Registrar CSE.
    -   c:
        - 'Registrar CSE sends response containing:'
        -   - Code = 2.01 (Created)
            - oneM2M-RSC= 2001
            - oneM2M-RQI=CRQI
            - Location-Path
            - content-format option
            - non-empty payload
    
    -   v: Client displays the response
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
        self.match('client', CoAP(opt=Opt(CoAPOptionOneM2MTY('14'))), 'fail')

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


