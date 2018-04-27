from ..common import *


class TD_LWM2M_1_INT_203(CoAPTestCase):
    """
---
testcase_id: TD_LWM2M_1.0_INT_203
uri : http://openmobilealliance.org/iot/lightweight-m2m-lwm2m
configuration: LWM2M_CFG_01
objective: 
  - Quering the Resources values of Device Object (ID:3) on the Client in TLV format
  - - Manufacturer Name (id:0)
    - Model number (ID:1)
    - Serial number (ID:2)
    - Firware Version (ID:3)
    - Error Code (ID:11)
    - Supported Binding and Modes (ID:16)
pre_conditions:
  - Device is registred at the LWM2M server
  - The Client supports the minimum Configuration C.1.
references: 'OMA-ETS-LightweightM2M-V1_0_1-20170926-A'
sequence:
  - step_id: 'TD_LWM2M_1.0_INT_203_step_01'
    type: stimuli
    node : lwm2m_server
    description:
      - 'Server sends a READ request (COAP GET) on device object instance'
      - - Type = 0 (CON)
        - Code = 1 (GET)

  - step_id: 'TD_LWM2M_1.0_INT_203_step_02'
    type: check
    description:
      - 'The request sent by the server contains'
      - - Type=0 and Code=1
        - Accept option = application/vnd.oma.lwm2m+tlv
        - Uri-Path option = 3/0


  - step_id: 'TD_LWM2M_1.0_INT_203_step_03'
    type: check
    description:
        - 'Client sends response containing'
        - - Code = 2.05 (Content)
          - content-format option=application/vnd.oma.lwm2m+tlv
          - Non-empty payload= contains the expected values of Manufacturer Name, Model number, Serial number, Firmware Version, error code, and supported Binding and modes resources. 

  - step_id: 'TD_LWM2M_1.0_INT_203_step_04'
    type: verify
    node: lwm2m_server
    description:
        - 'Requested data is successfully displayed'

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
        return [CoAP(type='con', code='get')]

    def run(self):
        self.match('server', CoAP(type='con', code='get', opt=self.uri('/3/0')), 'fail')
        self.match('server', CoAP(pl=(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('11542'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('11542'))), 'fail')
