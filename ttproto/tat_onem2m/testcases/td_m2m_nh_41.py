from ..common import *

class TD_M2M_NH_41(CoAPTestCase):
	"""
---
TD_M2M_NH_41:
        cfg: M2M_CFG_01
        obj: AE updates attribute in pollingChannel resource via a Update Request
        pre:
                - AE has created an Application Entity resource <AE> on Registrar CSE. 
                - AE has created a container resource <container> on Registrar CSE.
        ref: 'TS-0001 [1], clause 10.2.13.4; TS-0004 [2], clause 7.3.21.2.3'
        seq:
        -   s: 
            - 'AE is requested to send a pollingChannel Update Request to update the lifetime of the resource'
            -   - Type = 0 (CON)
                - Code = 3 (PUT)
                - Content-format option
                - Non-empty Payload

        -   c:
            -'Sent PUT request contains':
            -   - Type=0 and Code=3
                - Uri-Host = IP address or the FQDN of registrar CSE
                - Uri-Path = {CSEBaseName}/URI of <pollingChannel> resource
                - content-format=application/vnd.oneM2M-res+xml or application/vnd.oneM2M-res+json 
                - oneM2M-FR=AE-ID
                - oneM2M-RQI=token-string (-> CRQI)
                - Non-empty Payload

        -   v: 'Check if possible that the < pollingChannel > resource is updated in Registrar CSE'

        -   c:
            - 'Registrar CSE sends response containing:'
            -   - Code=2.04(changed)
                - oneM2M-RSC=2004
                - oneM2M-RQI=CRQI
                - Content-format=application/vnd.oneM2M-res+xml or application/vnd.oneM2M-res+json
                - Non-empty Payload

        -   v: 'AE indicates successfull operation'
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

			self.match("server", CoAP(code=Any(65, 68), pl=Not(b'')), 'fail')
			self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat())), 'fail')
			self.match('server', CoAP(opt=Opt(CoAPOptionOneM2MResponseStatusCode('2004'))), 'fail')
			self.match('server', CoAP(opt=Opt(CoAPOptionOneM2MRequestIdentifier(RIVAL))), 'fail')
