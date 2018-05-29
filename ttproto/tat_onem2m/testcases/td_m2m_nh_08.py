from ..common import *


class TD_M2M_NH_08(CoAPTestCase):
    """
---
TD_M2M_NH_08:
    cfg: M2M_CFG_01
    obj: AE updates attribute in <AE> resource
    pre: CSEBase resource has been created in registrar CSE with name {CSEBaseName} and
         AE has created a <AE> resource on registrar CSE with name {AE}
    ref: 'TS-0001, clause 10.2.1.3 and TS-0004, clause 7.3.5.2.3'
    seq:
    -   s:
        - 'AE is requested to send a PUT request with:'
        -   - Type = 0 (CON)
            - Code = 3 (PUT)
            - Non-empty payload
            - Content-format option
    -   c:
        - 'The request sent by the client contains:'
        -   - Type=0 and Code=3
            - oneM2M-FR option=AE-ID
            - oneM2M-RQI=token-string (CRQI)
            - contentFormat option
            - Non-Empty payload      
    -   v: Check if possible that the <AE> resource has been updated in registrar CSE. 
    -   c:
        - 'Registrar CSE sends response containing:'
        -   - Type = 0 (CON)
            - Code = 2.04 (UPDATED)
            - Token = CTOK
            - Content-format option
            - non-empty Payload
            - oneM2M-RSC option = 2004
            - oneM2M-RQI=CRQI
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
        """

        return [CoAP(type='con', code='put')]

    def run(self):
        self.match('client', CoAP(type="con", code="put", pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat())), "fail")
        self.match('client', CoAP(opt=Opt(CoAPOptionOneM2MFrom())), 'fail')
        if self.match('client', CoAP(opt=Opt(CoAPOptionOneM2MRequestIdentifier())), 'fail'):
            OPTS = self.coap['opt']
            RI = OPTS[CoAPOptionOneM2MRequestIdentifier]
            RIVAL = RI[2]
            self.next()

            self.match("server", CoAP(type='con', code=Any(65, 68), pl=Not(b'')), 'fail')
            self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat())), 'fail')
            self.match('server', CoAP(opt=Opt(CoAPOptionOneM2MResponseStatusCode('2004'))), 'fail')
            self.match('server', CoAP(opt=Opt(CoAPOptionOneM2MRequestIdentifier(RIVAL))), 'fail')

