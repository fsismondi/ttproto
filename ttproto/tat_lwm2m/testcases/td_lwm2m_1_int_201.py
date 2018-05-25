from ..common import *


class TD_LWM2M_1_INT_201(CoAPTestCase):
    """
---
testcase_id: TD_LWM2M_1.0_INT_201 
uri : http://openmobilealliance.org/iot/lightweight-m2m-lwm2m 
configuration: LWM2M_CFG_01 
objective:   
  - Querying the following data on the client (Device Object = ID 3) in text plain format 
  - - Manufacturer 
    - Model number 
    - Serial number 
pre_conditions: 
  - Device is registered at the LWM2M server
  - Client is supporting Plain Text data format (0)
  - The Client supports the minimum Configuration C.1.
references: 'OMA-ETS-LightweightM2M-V1_0_1-20170926-A'
sequence: 
  - step_id: 'TD_LWM2M_1.0_INT_201_step_01'
    type: stimuli 
    node : lwm2m_server 
    description: 
      - 'Server sends a READ request (COAP GET) on device object’s Manufacturer resource'       
      - - Type = 0 (CON)         
        - Code = 1 (GET) 

  - step_id: 'TD_LWM2M_1.0_INT_201_step_02' 
    type: check 
    description:
      - 'The request sent by the server contains'   
      - - Type=0 and Code=1  
          - Accept option = text/plain
          - Uri-Path option = 3/0/0

  - step_id: 'TD_LWM2M_1.0_INT_201_step_03'
    type: check
    description:       
      - 'Client sends response containing'         
      - - Code = 2.05 (Content)           
        - Non-empty Payload 

  - step_id: 'TD_LWM2M_1.0_INT_201_step_04' 
    type: verify 
    node: lwm2m_server 
    description:         
      - 'Requested data is successfully displayed' 

  - step_id: 'TD_LWM2M_1.0_INT_201_step_05' 
    type: stimuli 
    node : lwm2m_server 
    description: 
      - 'Server sends a READ request (COAP GET) on device object’s Model Number resource'       
      - - Type = 0 (CON)         
        - Code = 1 (GET) 

  - step_id: 'TD_LWM2M_1.0_INT_201_step_06' 
    type: check 
    description:       
      - 'The request sent by the server contains'       
      - - Type=0 and Code=1         
        - Accept option = text/plain                 
        - Uri-Path option = 3/0/1 

  - step_id: 'TD_LWM2M_1.0_INT_201_step_07' 
    type: check 
    description:         
      - 'Client sends response containing'         
      - - Code = 2.05 (Content)
        - Non-empty Payload
 
  - step_id: 'TD_LWM2M_1.0_INT_201_step_08' 
    type: verify 
    node: lwm2m_server 
    description:         
      - 'Requested data is successfully displayed' 

  - step_id: 'TD_LWM2M_1.0_INT_201_step_09' 
    type: stimuli 
    node : lwm2m_server 
    description: 
      - 'Server sends a READ request (COAP GET) on device object’s Serial Number resource'
      - - Type = 0 (CON)         
        - Code = 1 (GET)
 
  - step_id: 'TD_LWM2M_1.0_INT_201_step_10' 
    type: check 
    description:       
      - 'The request sent by the server contains'       
      - - Type=0 and Code=1         
        - Accept option = text/plain                 
        - Uri-Path option = 3/0/2
 
  - step_id: 'TD_LWM2M_1.0_INT_201_step_11' 
    type: check 
    description:         
      - 'Client sends response containing'         
      - - Code = 2.05 (Content)           
        - Non-empty Payload

  - step_id: 'TD_LWM2M_1.0_INT_201_step_12' 
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
        self.match('server', CoAP(type='con', code='get', opt=self.uri('/3/0/0')), 'fail')
        self.match('server', CoAP(pl=(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('40'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('40'))), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='get', opt=self.uri('/3/0/1')), 'fail')
        self.match('server', CoAP(pl=(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('40'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('40'))), 'fail')
        
        self.next()

        self.match('server', CoAP(type='con', code='get', opt=self.uri('/3/0/2')), 'fail')
        self.match('server', CoAP(pl=(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('40'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('40'))), 'fail')
