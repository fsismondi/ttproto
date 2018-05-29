from ..common import *


class TD_M2M_NH_30 (CoAPTestCase):
    """
---
TD_M2M_NH_30:
    cfg: M2M_CFG_01
    obj: AE delete request is rejected due to accessControlPolicy.
    pre: CSEBase resource has been created in registrar CSE with name {CSEBaseName},
         AE has created a <AE> resource on registrar CSE with name {AE},
         accessControlPolicy resource has been created in registrar CSE under <AE> resource with name {accessControlPolicyName}, which forbids to delete container,
         and AE has created a <container> resource on registrar CSE under <AE>, with name {containerName}.
    ref: 'TS-0004, clause 7.3.1.2'
    seq:
    -   s:
        - 'AE is requested to send a container Delete Request for resource <container>'
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
        -   - Code = 4.03 (Forbidden)
            - Message ID = CMID, Token = CTOK
            - Empty Payload
            - oneM2M-RSC=4103
            - oneM2M-RQI=CRQI
    -   v: 'Check if possible that the <container> resource has not been removed from registrar
CSE.'
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

            self.match('server', CoAP(code=4.03, mid=CMID, tok=CTOK, pl=(b'')), 'fail')
            self.match('server', CoAP(opt=Opt(CoAPOptionOneM2MResponseStatusCode('4103'))), 'fail')
            self.match('server', CoAP(opt=Opt(CoAPOptionOneM2MRequestIdentifier(RIVAL))), 'fail')
