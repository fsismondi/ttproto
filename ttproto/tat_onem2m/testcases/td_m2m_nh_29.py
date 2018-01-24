from ..common import *


class TD_M2M_NH_29 (CoAPTestCase):
    """
---
TD_M2M_NH_29:
    cfg: M2M_CFG_01
    obj: AE deletes accessControlPolicy resource.
    pre: CSEBase resource has been created in registrar CSE with name {CSEBaseName},
         AE has created a <AE> resource on registrar CSE with name {AE} and
         accessControlPolicy resource has been created in registrar CSE under <AE> resource with name {accessControlPolicyName}.
    ref: 'TS-0001, clause 10.2.21.4 and TS-0004, clause 7.3.1.2'
    seq:
    -   s:
        - 'AE is requested to send a accessControlPolicy DELETE request to Registrar CSE:'
        -   - Type = 0 (CON)
            - Code = 4 (DELETE)
    -   c:
        - 'The request sent by the client contains:'
        -   - Type=0 and Code=4
            - "Client-generated Message ID (\u2794 CMID)"
            - "Client-generated Token (\u2794 CTOK)"
            - oneM2M-FR=AE-ID
            - oneM2M-RQI=token-string (CRQI)
            - Empty payload
    -   c:
        - 'Registrar CSE sends response containing:'
        -   - Code = 2.02 (OK)
            - Message ID = CMID, Token = CTOK
            - Empty Payload
            - oneM2M-RSC=2002
            - oneM2M-RQI=CRQI
    -   v: Check if possible that the <AE> resource has been removed from registrar CSE
    -   v: AE indicates a successuful operation
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
