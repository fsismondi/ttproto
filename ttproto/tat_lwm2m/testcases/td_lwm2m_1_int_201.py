from ..common import *


class TD_LWM2M_1_INT_201(CoAPTestCase):
    """
---
TD_LWM2M_1_INT_201:
    testcase_id: TD_LWM2M_1_INT_201
uri : http://openmobilealliance.org/iot/lightweight-m2m-lwm2m
configuration: LWM2M_CFG_01
objective: 
  - Quering the following data on the client (Device Object = ID 3) in plain text format
  - - Manufacturer
    - Model number
    - Serial number
pre_conditions: Device is registred at the LWM2M server
notes: null
references: 'OMA-ETS-LightweightM2M-V1_0-20160829-C'
    seq:
    - step_id: 'TD_LWM2M_1_INT_201_step_01'
    type: stimuli
    node : coap_server
    description:
      - 'Server sends a READ request (COAP GET) on device object resources'
      - - Type = 0 (CON)
        - Code = 1 (GET)

  - step_id: 'TD_LWM2M_1_INT_201_step_02'
    type: check
    description:
      - 'The request sent by the server contains'
      - - Type=0 and Code=1
        - Accept option = text/plain


  - step_id: 'TD_LWM2M_1_INT_201_step_03'
    type: check
    description:
        - 'Client sends response containing'
        - - Code = 2.05 (Content)
          - Manufacturer
          - Model number
          - Serial number

  - step_id: 'TD_LWM2M_1_INT_201_step_04'
    type: verify
    node: coap_server
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
        return [CoAP(code='get')]

    def run(self):
        self.match('server', CoAP(type='con', code='get', opt=self.uri('/3/0')))
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept())), 'fail')
        CMID = self.coap['mid']
        CTOK = self.coap['tok']

        self.next()

        if self.match('client', CoAP(code=2.05, mid=CMID, tok=CTOK, pl=Not(b'')), None):
            self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat())), 'fail')
