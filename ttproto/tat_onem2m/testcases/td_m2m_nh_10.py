from ..common import *


class TD_M2M_NH_10(CoAPTestCase):
    """
---
TD_M2M_NH_10:
    cfg: M2M_CFG_01
    obj: AE creates a container resource in registrar CSE via a container Create Request.
    pre: AE has created an application resource <AE> on registrar CSE. 
    ref: 'TS-0001, clause 10.2.4.1 ; TS-0004, clause 7.3.5.2.1'
    seq:
    -   s: "AE is requested to send a POST request to CSE to create a <container>"
    -   c:
        - 'The request sent by the client contains:'
        -   - Type = 0 (CON
            - Code = 2 (POST)
            - Non-empty payload
            - Content-format option
            - oneM2M-TY "3"
            - oneM2M-FR (originator) "AE_ID"
            - oneM2M-RQI "token-string" (CRQI)
    -   v: Check if possible that the <container> resource is created in registrar CSE. 
    -   c:
        - 'Registrar CSE sends response containing:'
        -   - Code = 2.01 (Created)
            - oneM2M-RSC= 2001
            - oneM2M-RQI=CRQI
            - Location-Path
            - contentFormat option
            - non-empty payload
    
    -   v: AE indicates successful operation
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
        return [CoAP(type='con', code='post')]


    def run (self):
        self.match('client', CoAP (type="con", code="post",pl=Not(b"")), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat())), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionOneM2MFrom())), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionOneM2MTY('3'))), 'fail')
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

