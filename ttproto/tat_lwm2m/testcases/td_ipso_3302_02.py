from ..common import *


class TD_IPSO_3302_02(CoAPTestCase):
    """
testcase_id: TD_IPSO_3302_02
uri : http://openmobilealliance.org/iot/lightweight-m2m-lwm2m
configuration: LWM2M_CFG_01
objective: 
  - Querying of Digital input state resource (ID = 5500) value of Presence object (ID = 3302) in plain text format
pre_conditions: Device is registered at the LWM2M server
sequence:
  - step_id: 'TD_IPSO_3302_02_step_01'
    type: stimuli
    node : lwm2m_server
    description:
      - 'Server sends a READ request (COAP GET) on Digital input state resource of Presence object'
      - - Type = 0 (CON)
        - Code = 1 (GET)

  - step_id: 'TD_IPSO_3302_02_step_02'
    type: check
    description:
      - 'The request sent by the server contains'
      - - Type=0 and Code=1
        - Accept option = text/plain
        - Uri-Path option = 3302/0/5500

  - step_id: 'TD_IPSO_3302_02_step_03'
    type: check
    description:
        - 'Client sends response containing'
        - - Code = 2.05 (Content)
          - content-format option = text/plain
          - Non-empty Payload

  - step_id: 'TD_IPSO_3302_02_step_04'
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
        self.match('server', CoAP(type='con', code='get', opt=self.uri('3302/0/5500')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('40'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('40'))), 'fail')


     
