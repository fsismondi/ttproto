from ..common import *


class TD_M2M_NH_50 (CoAPTestCase):
    """
---
TD_M2M_NH_50:
    cfg: M2M_CFG_01
    obj: AE deletes a <oldest> resource of a <container> and the Registrar CSE points an oldest <contentInstance>
         among the existing contentInstances to the <oldest> resource of the <container>.
    pre: AE has created an Application Entity resource <AE> on Registrar CSE,
         AE has created a container resource <container> on Registrar CSE,
         and AE has created more than one contentInstance <contentInstance> as child of <container> on Registrar CSE.
    ref: 'TS-0001, clause 10.2.22.2 and TS-0004, clause 7.4.28.2.5'
    seq:
    -   s:
        - 'AE sends a DELETE request to the <oldest> resource of the <container>:'
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
    -   v: AE indicates successful DELETE operation of a <oldest> resource.
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
