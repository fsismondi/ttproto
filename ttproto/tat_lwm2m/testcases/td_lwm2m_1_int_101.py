from ..common import *


class TD_LWM2M_1_INT_101(CoAPTestCase):
    """
---
testcase_id: TD_LWM2M_1.0_INT_101
uri: http://openmobilealliance.org/iot/lightweight-m2m-lwm2m
configuration: LWM2M_CFG_01
objective: Test that the Client registers with the server. 
pre_conditions:
  - The Client supports the minimum Configuration C.1.
  - - LWM2M Server Object (ID = 1) Instance 0 with mandatory resources and Short Server ID = 1
  - - LWM2M Security Object (ID = 0) Instance 0 with mandatory resources and Bootstrap Server = False
  - - LWM2M Device Object (ID = 3) Instance 0 with mandatory resources. 
  - Device is turned on. 
  - The bootstrap procedure has been completed or the required bootstrap information is available to the Client. 
references: 'OMA-ETS-LightweightM2M-V1_0_1-20170926-A'
sequence:
  - step_id: 'TD_LWM2M_1.0_INT_101_step_01'
    type: stimuli
    node: lwm2m_client
    description:
      - 'LwM2M client sends a Registration message (CoAP POST) to LwM2M server'
      - - Type = 0 (CON)
        - Code = 2 (POST)
        - Content-format option=application/link-format
        - Non-empty Payload

  - step_id: 'TD_LWM2M_1.0_INT_101_step_02'
    type: check
    description:
      - 'Sent POST request contains'
      - - Type=0 and Code=2
        - Non-empty payload= A Media-Type payload where each Object is described as a Link according to content-format option.
        - content-format=application/link-format
        - Uri-Path option = /rd
        - Uri-Query option = 'ep={endPointClientName}'
        - Uri-Query option = 'lt={lifetime}'
        - Uri-Query option = 'sms={MSISDN}'
        - Uri-Query option = 'lwm2m={version}'
        - Uri-Query option = 'b={binding}'

  - step_id: 'TD_LWM2M_1.0_INT_101_step_03'
    type: check
    description:
      - 'LwM2M server sends response containing'
      - - Code = 2.01 (Created)
        - content-format=application/link-format
        - LocationPath option = the path to use for updating or deleting the registration
        - Non-empty payload

  - step_id: 'TD_LWM2M_1.0_INT_101_step_04'
    type: verify
    node: lwm2m_client
    description:
      - 'LwM2M client indicates successful operation'
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
        return [CoAP(type='con', code='post')]

    def run(self):
        self.match('client', CoAP(type='con', code='post', opt=self.uri('/rd')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('40'))), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionAccept('40'))), 'fail')
        opts = list (filter ((lambda o: isinstance (o, CoAPOptionUriQuery)), self.frame.coap["opt"]))
        if len (opts) < 1:
            self.setverdict ("inconclusive", "expect at least one UriQuery option")
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('40'))), 'fail')


        self.next()

        self.match('server', CoAP(code=2.01, pl=Not(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat('40'))), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionLocationPath())), 'fail')
