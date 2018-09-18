from ..common import *


class TD_LWM2M_1_INT_241(CoAPTestCase):
    """
---
testcase_id: TD_LWM2M_1.0_INT_241
uri : http://openmobilealliance.org/iot/lightweight-m2m-lwm2m
configuration: LWM2M_CFG_01
objective: 
  - Test that the Device can be remotely rebbot via the Device Object (ID:3)
pre_conditions: 
  - The Client supports the minimum Configuration C.1.
  - Device is switched on
  - Client is registered with the Server. (Client might be in a state that requires a reboot)
references: 'OMA-ETS-LightweightM2M-V1_0_1-20170926-A'
sequence:
  - step_id: 'TD_LWM2M_1.0_INT_241_step_01'
    type: stimuli
    node : lwm2m_server
    description:
      - 'LwM2M server performs Execute (CoAP POST) operation on Reboot Resource of Device Object (ID:3) Instance'
      - - Type = 0 (CON)
        - Code = 2 (POST)

  - step_id: 'TD_LWM2M_1.0_INT_241_step_02'
    type: check
    description:
      - 'The request sent by the server contains'
      - - Type=0 and Code=2
        - Uri-Path option= 3/0/4

  - step_id: 'TD_LWM2M_1.0_INT_241_step_03'
    type: check
    description:
        - 'LwM2M client sends response containing'
        - - Code = 2.04 (Changed)

  - step_id: 'TD_LWM2M_1.0_INT_241_step_04'
    type: verify
    node: LwM2M Server
    description:
        - 'Device reboots successfully and re-registers at the server again.'

  - step_id: 'TD_LWM2M_1.0_INT_241_step_05'
    type: stimuli 
    node: lwm2m_client
    description:
      - 'LwM2M client sends a Registration message (CoAP POST) to LwM2M server'
      - - Type = 0 (CON)
        - Code = 2 (POST)
        - Content-format option=application/link-format
        - Non-empty Payload

  - step_id: 'TD_LWM2M_1.0_INT_241_step_06'
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

  - step_id: 'TD_LWM2M_1.0_INT_241_step_07'
    type: check
    description:
      - 'LwM2M server sends response containing'
      - - Code = 2.01 (Created)
        - content-format=application/link-format
        - LocationPath option = the path to use for updating or deleting the registration
        - Non-empty payload

  - step_id: 'TD_LWM2M_1.0_INT_241_step_08'
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
        self.match('server', CoAP(type='con', code='post', opt=self.uri('/3/0/4')), 'fail')
        self.match('server', CoAP(pl=(b'')), 'fail')

        self.next()

        self.match('client', CoAP(code=Any(65, 68)), 'fail')

        self.next()

        self.match('client', CoAP(type='con', code='post', opt=self.uri('/rd')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('40'))), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionAccept('40'))), 'fail')
        opts = list(filter((lambda o: isinstance(o, CoAPOptionUriQuery)), self.frame.coap["opt"]))
        if len(opts) < 1:
            self.setverdict("inconclusive", "expect at least one UriQuery option")
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('40'))), 'fail')

        self.next()

        self.match('server', CoAP(code=2.01, pl=Not(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat('40'))), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionLocationPath())), 'fail')
