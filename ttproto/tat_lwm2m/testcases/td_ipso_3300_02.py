from ..common import *


class TD_IPSO_3300_02(CoAPTestCase):
    """
---

testcase_id: TD_IPSO_3300_02
uri : http://openmobilealliance.org/iot/lightweight-m2m-lwm2m
configuration: LWM2M_CFG_01
objective: 
  - Querying Generic Sensor Object instance (ID = 3300) representation in JSON format on LwM2M client
pre_conditions: Device is registered at the LWM2M server
sequence:
  - step_id: 'TD_IPSO_3300_02_step_01'
    type: stimuli
    node : lwm2m_server
    description:
      - 'Server sends a READ request (COAP GET) on Generic Sensor Object'
      - - Type = 0 (CON)
        - Code = 1 (GET)

  - step_id: 'TD_IPSO_3300_02_step_02'
    type: check
    description:
      - 'The request sent by the server contains'
      - - Type=0 and Code=1
        - Accept option = application/vnd.oma.lwm2m+json
        - Uri-Path option = 3300/0

  - step_id: 'TD_IPSO_3300_02_step_03'
    type: check
    description:
        - 'Client sends response containing'
        - - Code = 2.05 (Content)
          - content-format option = application/vnd.oma.lwm2m+json
          - Non-empty Payload

  - step_id: 'TD_IPSO_3300_02_step_04'
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
        self.match('server', CoAP(type='con', code='get', opt=self.uri('/3300/0')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('11543'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('11543'))), 'fail')

        validation = validate(str(self.coap['pl']),'3300')
        self.set_verdict(validation[0], validation[1])
