# -*- coding: utf-8 -*-

"""
This module provides the API message formats used in F-Interop.

The idea is to be able to have an
- organized and centralized way of dealing with the big amount of messages formats used in the platform;
- to be able to import (or just copy/paste) these messages formats from any component in the F-Interop platform,
- re-use this also for the integration testing;
- to have version control the messages e.g. messages_testcase_start API v1 and API v2;
- to have a direct way of exporting this as doc.

Usage:
------
>>> from messages import * # doctest: +SKIP
>>> m = MsgTestCaseSkip()
>>> m
MsgTestCaseSkip(_type = testcoordination.testcase.skip, _api_version = 0.1.2, testcase_id = TD_COAP_CORE_02_v01, )
>>> m.routing_key
'control.testcoordination'
>>> m.message_id # doctest: +SKIP
'802012eb-24e3-45c4-9dcc-dc293c584f63'
>>> m.testcase_id
'TD_COAP_CORE_02_v01'

# also we can modify some of the fields (rewrite the default ones)
>>> m = MsgTestCaseSkip(testcase_id = 'TD_COAP_CORE_03_v01')
>>> m
MsgTestCaseSkip(_type = testcoordination.testcase.skip, _api_version = 0.1.2, testcase_id = TD_COAP_CORE_03_v01, )
>>> m.testcase_id
'TD_COAP_CORE_03_v01'

# and even export the message in json format (for example for sending the message though the amqp event bus)
>>> m.to_json()
'{"_type": "testcoordination.testcase.skip", "_api_version": "0.1.2", "testcase_id": "TD_COAP_CORE_03_v01"}'

# We can use the Message class to import json into Message objects:
>>> m=MsgTestSuiteStart()
>>> m.to_json()
'{"_type": "testcoordination.testsuite.start", "_api_version": "0.1.2"}'
>>> json_message = m.to_json()
>>> obj=Message.from_json(json_message)
>>> type(obj)
<class '__main__.MsgTestSuiteStart'>

# We can use the library for generating error responses to the requests:
# the request:
>>> m = MsgSniffingStart()
>>>
# the error reply (note that we pass the message of the request to build the reply):
>>> err = MsgErrorReply(m)
>>> err
MsgErrorReply(_type = sniffing.start, _api_version = 0.1.2, ok = False, error_code = Some error code TBD, error_message = Some error message TBD, )
>>> m.reply_to
'control.sniffing.service.reply'
>>> err.routing_key
'control.sniffing.service.reply'

>>> m.correlation_id # doctest: +SKIP
'360b0f67-4455-43e3-a00f-eca91f2e84da'
>>> err.correlation_id # doctest: +SKIP
'360b0f67-4455-43e3-a00f-eca91f2e84da'

"""

from collections import OrderedDict
import json
import uuid
import logging

API_VERSION = '0.1.10'


# TODO use metaclasses instead?
# TODO Define also a reply method which provides amessage with routig key for the reply, correlation id, reply_to,etc

class NonCompliantMessageFormatError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Message:
    def __init__(self, **kwargs):
        global API_VERSION

        # hard copy the message template
        self._msg_data = {k: v for k, v in self._msg_data_template.items()}

        # init properties
        self._properties = dict(
                content_type='application/json',
                message_id=str(uuid.uuid4()),
        )

        try:
            if self.routing_key.endswith('.service'):
                self._properties['reply_to'] = '%s.%s' % (self.routing_key, 'reply')
                self._properties['correlation_id'] = self._properties['message_id']
        except AttributeError:
            pass

        # rewrite default data fields with the passed args
        self._msg_data.update(kwargs)

        # add API's version
        self._msg_data['_api_version'] = API_VERSION

        # add values as objects attributes
        for key in self._msg_data:
            setattr(self, key, self._msg_data[key])

        # add props as objects attributes
        for key in self._properties:
            setattr(self, key, self._properties[key])

    def to_dict(self) -> OrderedDict:
        resp = OrderedDict()
        # let's use sorted so API returns items inside always in the same order
        for field in sorted(self._msg_data.keys()):
            resp[field] = getattr(self, field)

        # for readability
        if 'ok' in resp:
            resp.move_to_end('ok', False)
        if '_api_version' in resp:
            resp.move_to_end('_api_version', False)
        if '_type' in resp:
            resp.move_to_end('_type', False)

        return resp

    def to_json(self):
        return json.dumps(self.to_dict())

    def get_properties(self) -> dict:
        resp = OrderedDict()
        for field in self._properties:
            resp[field] = getattr(self, field)
        return resp

    def __str__(self):
        str = ' - ' * 20 + '\n'
        str += 'Message routing key: %s' % self.routing_key
        str += '\n'
        str += 'Message properties: %s' % json.dumps(self.get_properties())
        str += '\n'
        str += 'Message body: %s' % self.to_json()
        str += '\n' + ' - ' * 20
        return str

    def update_properties(self, **kwargs):
        for key, value in kwargs.items():
            if key in self._properties:
                setattr(self, key, value)

    @classmethod
    def from_json(cls, body):
        """
        :param body: json string or string encoded as utf-8
        :return:  Message object generated from the body
        :raises NonCompliantMessageFormatError: If the message cannot be build from the provided json
        """

        if type(body) is str:
            message_dict = json.loads(body)
        # Note: pika re-encodes json.dumps strings as utf-8 for some reason, the following line undoes this
        elif type(body) is bytes:
            message_dict = json.loads(body.decode('utf-8'))
        else:
            raise NonCompliantMessageFormatError('Not a Json')

        # check fist if it's a response
        if 'ok' in message_dict:
            # cannot build a complete reply message just from the json representation
            return

        message_type = message_dict['_type']
        if message_type in message_types_dict:
            return message_types_dict[message_type](**message_dict)
        else:
            raise NonCompliantMessageFormatError('Cannot load json message: %s' % str(body))

    def __repr__(self):
        ret = '%s(' % self.__class__.__name__
        for key, value in self.to_dict().items():
            ret += '%s = %s, ' % (key, value)
        ret += ')'
        return ret


class MsgReply(Message):
    """
    Auxiliary class which creates replies messages with fields based on the request.
    Routing key, corr_id and _type are generated based on the request message
    """

    def __init__(self, request_message, **kwargs):
        assert request_message

        self.routing_key = request_message.routing_key + ".reply"

        # if not data template, then let's build one for a reply
        # (possible when creating a MsgReply directly and not by using subclass)
        if not hasattr(self, '_msg_data_template'):
            self._msg_data_template = {
                '_type': request_message._type,
                'ok': True,
            }

        super().__init__(**kwargs)

        # overwrite correlation id template and attribute
        self._properties['correlation_id'] = request_message.correlation_id
        self.correlation_id = request_message.correlation_id


class MsgErrorReply(MsgReply):
    """
    F-Interop conventions:
        - if event is a service request then the routing keys is control.someFunctionality.service
        also, its reply will be control.someFunctionality.service.reply
        - reply.correlation_id = request.correlation_id

    """

    def __init__(self, request_message, **kwargs):
        assert request_message
        # msg_data_template doesnt include _type cause this class is generic, we can only get this at init from request
        # so, let's copy the _type from request and let the MsgReply handle the rest of the fields
        self._msg_data_template['_type'] = request_message._type
        super().__init__(request_message, **kwargs)

    _msg_data_template = {
        'ok': False,
        'error_message': 'Some error message TBD',
        'error_code': 'Some error code TBD'
    }


###### SESSION MESSAGES ######

class MsgSessionTerminate(Message):
    """
    Testing Tool MUST-implement API endpoint
    GUI, (or Orchestrator?) -> Testing Tool
    Testing tool should stop all it's processes gracefully.
    """
    routing_key = 'control.session.terminate'

    _msg_data_template = {
        '_type': 'session.terminate',
    }


###### TEST COORDINATION MESSAGES ######

class MsgTestSuiteStart(Message):
    """
    Testing Tool MUST-implement API endpoint
    GUI -> Testing Tool
    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        '_type': "testcoordination.testsuite.start",
    }


class MsgTestCaseReady(Message):
    """
    Testing Tool MUST-implement notification.
    Testing Tool -> GUI

    Used to indicate to the GUI (or automated-iut) which is the next test case to be executed.
    This message is normally followed by a MsgTestCaseStart (from GUI-> Testing Tool)
    """

    routing_key = 'control.testcoordination'

    _msg_data_template = {
        "_type": "testcoordination.testcase.ready",
        "message": "Next test case to be executed is TD_COAP_CORE_01_v01",
        "testcase_id": "TD_COAP_CORE_01_v01",
        "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_01_v01",
        "objective": "Perform GET transaction(CON mode)",
        "state": None
    }


class MsgTestCaseStart(Message):
    """
    Testing Tool MUST-implement API endpoint
    GUI -> Testing Tool
    Message used for indicating the testing tool to start the test case (the one previously selected)
    """
    routing_key = "control.testcoordination"

    _msg_data_template = {
        '_type': "testcoordination.testcase.start",
    }


class MsgTestCaseConfiguration(Message):
    """
    Testing Tool MUST-implement notification
    Testing Tool -> GUI
    Messages used to indicate GUI which configuration to use.
    """
    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.testcase.configuration",
        "configuration_id": "COAP_CFG_01_v01",
        "node": "coap_server",
        "message":
            ["CoAP servers running service at [bbbb::2]:5683",
             "CoAP servers are requested to offer the following resources",
             ["/test", "Default test resource", "Should not exceed 64bytes"],
             ["/seg1/seg2/seg3", "Long path ressource", "Should not exceed 64bytes"],
             ["/query", "Ressource accepting query parameters", "Should not exceed 64bytes"],
             ["/separate",
              "Ressource which cannot be served immediately and which cannot be acknowledged in a piggy-backed way",
              "Should not exceed 64bytes"],
             ["/large", "Large resource (>1024 bytes)", "shall not exceed 2048bytes"],
             ["/large_update", "Large resource that can be updated using PUT method (>1024 bytes)",
              "shall not exceed 2048bytes"],
             ["/large_create", "Large resource that can be  created using POST method (>1024 bytes)",
              "shall not exceed 2048bytes"],
             ["/obs", "Observable resource which changes every 5 seconds", "shall not exceed 2048bytes"],
             ["/.well-known/core", "CoRE Link Format", "may require usage of Block options"]
             ]
    }


class MsgTestCaseStop(Message):
    """
    Testing Tool MUST-implement API endpoint
    GUI -> Testing Tool
    Message used for indicating the testing tool to stop the test case (the one running)
    """

    routing_key = 'control.testcoordination'

    _msg_data_template = {
        '_type': 'testcoordination.testcase.stop',
    }


class MsgTestCaseRestart(Message):
    """
    Testing Tool MUST-implement API endpoint
    GUI -> Testing Tool
    """

    routing_key = 'control.testcoordination'

    _msg_data_template = {
        '_type': 'testcoordination.testcase.restart',
    }


class MsgStepExecute(Message):
    """
    Testing Tool MUST-implement notification.
    Testing Tool -> GUI

    Used to indicate to the GUI (or automated-iut) which is the step to be executed by the user (or automated-IUT)
    """

    routing_key = 'control.testcoordination'

    _msg_data_template = {
        "_type": "testcoordination.step.execute",
        "message": "Next test step to be executed is TD_COAP_CORE_01_v01_step_01",
        "step_id": "TD_COAP_CORE_01_v01_step_01",
        "step_type": "stimuli",
        "step_info": [
            "Client is requested to send a GET request with",
            "Type = 0(CON)",
            "Code = 1(GET)"
        ],
        "step_state": "executing",
        "node": "coap_client",
        "node_execution_mode": "user_assisted"
    }


class MsgStimuliExecuted(Message):
    """
    Testing Tool MUST-implement API endpoint
    GUI (or automated-IUT)-> Testing Tool
    """

    routing_key = 'control.testcoordination'

    _msg_data_template = {
        '_type': 'testcoordination.step.stimuli.executed',
    }


class MsgCheckResponse(Message):
    """
    Testing Tools'internal call.
    In the context of IUT to IUT test execution, this message is used for indicating that the previously executed
    messages (stimuli message and its reply) CHECK or comply to what is described in the Test Description.
    Testing tools' coordinator -> Testing Tool's analyzer (TAT)
    Not used in CoAP testing Tool (analysis of traces is done post mortem)
    """

    routing_key = 'control.testcoordination'

    _msg_data_template = {
        '_type': 'testcoordination.step.check.response',
        'partial_verdict': 'pass',
        'description': 'TAT says: step complies (checks) with specification'
    }


class MsgVerifyResponse(Message):
    """
    Testing Tool MUST-implement API endpoint
    Message provided by user declaring if the IUT VERIFY the step previously executed as described in the Test
    Description.
    GUI (or automated-IUT)-> Testing Tool
    """

    routing_key = 'control.testcoordination'

    _msg_data_template = {
        '_type': 'testcoordination.step.verify.response',
        'verify_response': True,
        'response_type': 'bool'
    }


class MsgTestCaseFinish(Message):
    """
    Testing Tool MUST-implement API endpoint
    GUI (or automated-IUT)-> Testing Tool
    Not used in CoAP Testing Tool (test coordinator deduces it automatically by using the testcase's step sequence)
    """

    routing_key = 'control.testcoordination'

    _msg_data_template = {
        '_type': 'testcoordination.testcase.finish',
    }


class MsgTestCaseSkip(Message):
    """
    Testing Tool MUST-implement API endpoint
    GUI (or automated-IUT)-> Testing Tool

    - testcase_id (optional) : if not provided then current tc is skipped
    """

    routing_key = 'control.testcoordination'

    _msg_data_template = {
        '_type': 'testcoordination.testcase.skip',
        'testcase_id': 'TD_COAP_CORE_02_v01',
    }


class MsgTestCaseSelect(Message):
    """
    Testing Tool MUST-implement API endpoint
    GUI (or automated-IUT)-> Testing Tool
    """

    routing_key = 'control.testcoordination'

    _msg_data_template = {
        '_type': 'testcoordination.testcase.select',
        'testcase_id': 'TD_COAP_CORE_03_v01',
    }


class MsgTestSuiteAbort(Message):
    """
    Testing Tool MUST-implement API endpoint
    GUI (or automated-IUT)-> Testing Tool
    """

    routing_key = 'control.testcoordination'

    _msg_data_template = {
        '_type': 'testcoordination.testsuite.abort',
    }


class MsgTestSuiteGetStatus(Message):
    """
    Testing Tool SHOULD-implement API endpoint
    Describes current state of the test suite.
    Format for the response not standardised.

    GUI -> Testing Tool
    """

    routing_key = 'control.testcoordination.service'

    _msg_data_template = {
        '_type': 'testcoordination.testsuite.getstatus',
    }


class MsgTestSuiteGetStatusReply(MsgReply):
    """
    Testing Tool SHOULD-implement API endpoint
    Describes current state of the test suite.
    Format for the response not standardised.

    Testing Tool -> GUI

    """

    routing_key = 'control.testcoordination.service.reply'

    _msg_data_template = {
        '_type': 'testcoordination.testsuite.getstatus.reply',
        'ok': True,
        "status": {
            "current_tc":
                {
                    "state": "executing",
                    "testcase_id": "TD_COAP_CORE_01_v01"
                },
            "current_step":
                {
                    "step_id": "TD_COAP_CORE_01_v01_step_01",
                    "step_type": "stimuli",
                    "step_info":
                        ["Client is requested to send a GET request with", "Type = 0(CON)", "Code = 1(GET)"],
                    "step_state": "executing",
                    "node": "coap_client",
                    "node_execution_mode": "user_assisted"
                }
        }
    }


class MsgTestSuiteGetTestCases(Message):
    """
    Testing Tool's MUST-implement API endpoint
    GUI -> Testing Tool
    GUI MUST implement
    """

    routing_key = 'control.testcoordination.service'

    _msg_data_template = {
        '_type': 'testcoordination.testsuite.gettestcases',
    }


class MsgTestSuiteGetTestCasesReply(MsgReply):
    """
    Testing Tool's MUST-implement API endpoint
    Testing Tool -> GUI
    """

    routing_key = 'control.testcoordination.service.reply'

    _msg_data_template = {
        '_type': 'testcoordination.testsuite.gettestcases.reply',
        'ok': True,
        "tc_list": [
            {
                "testcase_id": "TD_COAP_CORE_01_v01",
                "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_01_v01",
                "objective": "Perform GET transaction(CON mode)",
                "state": None
            },
            {
                "testcase_id": "TD_COAP_CORE_02_v01",
                "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_02_v01",
                "objective": "Perform DELETE transaction (CON mode)",
                "state": None
            },
            {
                "testcase_id": "TD_COAP_CORE_03_v01",
                "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_03_v01",
                "objective": "Perform PUT transaction (CON mode)",
                "state": None
            }
        ]
    }


class MsgTestCaseVerdict(Message):
    """
    Testing Tool MUST-implement notification.
    Testing Tool -> GUI

    Used to indicate to the GUI (or automated-iut) which is the final verdict of the testcase.
    """

    routing_key = 'control.testcoordination'

    _msg_data_template = {
        "_type": "testcoordination.testcase.verdict",
        "verdict": "pass",
        "description": "No interoperability error was detected,",
        "partial_verdicts": [
            ["TD_COAP_CORE_01_v01_step_02", None, "CHECK postponed", ""],
            ["TD_COAP_CORE_01_v01_step_03", None, "CHECK postponed", ""],
            ["TD_COAP_CORE_01_v01_step_04", "pass",
             "VERIFY step: User informed that the information was displayed correclty on his/her IUT", ""],
            ["CHECK_1_post_mortem_analysis", "pass",
             "<Frame   3: [bbbb::1 -> bbbb::2] CoAP [CON 43211] GET /test> Match: CoAP(type=0, code=1)"],
            ["CHECK_2_post_mortem_analysis", "pass",
             "<Frame   4: [bbbb::2 -> bbbb::1] CoAP [ACK 43211] 2.05 Content > Match: CoAP(code=69, mid=0xa8cb, tok=b'', pl=Not(b''))"],
            ["CHECK_3_post_mortem_analysis", "pass",
             "<Frame   4: [bbbb::2 -> bbbb::1] CoAP [ACK 43211] 2.05 Content > Match: CoAP(opt=Opt(CoAPOptionContentFormat()))"]],
        "testcase_id": "TD_COAP_CORE_01_v01",
        "testcase_ref": "http://f-interop.paris.inria.fr/tests/TD_COAP_CORE_01_v01",
        "objective": "Perform GET transaction(CON mode)", "state": "finished"
    }


class MsgTestSuiteReport(Message):
    """
    Testing Tool MUST-implement notification.
    Testing Tool -> GUI

    Used to indicate to the GUI (or automated-iut) the final results of the test session.
    """

    routing_key = 'control.testcoordination'

    _msg_data_template = {
        "_type": "testcoordination.testsuite.finished",
        "TD_COAP_CORE_01_v01":
            {
                "verdict": "pass",
                "description": "No interoperability error was detected,",
                "partial_verdicts":
                    [
                        ["TD_COAP_CORE_01_v01_step_02", None, "CHECK postponed", ""],
                        ["TD_COAP_CORE_01_v01_step_03", None, "CHECK postponed", ""],
                        ["TD_COAP_CORE_01_v01_step_04", "pass",
                         "VERIFY step: User informed that the information was displayed correclty on his/her IUT", ""],
                        ["CHECK_1_post_mortem_analysis", "pass",
                         "<Frame   3: [bbbb::1 -> bbbb::2] CoAP [CON 43211] GET /test> Match: CoAP(type=0, code=1)"],
                        ["CHECK_2_post_mortem_analysis", "pass",
                         "<Frame   4: [bbbb::2 -> bbbb::1] CoAP [ACK 43211] 2.05 Content > Match: CoAP(code=69, mid=0xa8cb, tok=b'', pl=Not(b''))"],
                        [
                            "CHECK_3_post_mortem_analysis",
                            "pass",
                            "<Frame   4: [bbbb::2 -> bbbb::1] CoAP [ACK 43211] 2.05 Content > Match: CoAP(opt=Opt(CoAPOptionContentFormat()))"]
                    ]
            },

        "TD_COAP_CORE_02_v01":
            {
                "verdict": "pass",
                "description": "No interoperability error was detected,",
                "partial_verdicts": [
                    ["TD_COAP_CORE_02_v01_step_02", None, "CHECK postponed", ""],
                    ["TD_COAP_CORE_02_v01_step_03", None, "CHECK postponed", ""],
                    ["TD_COAP_CORE_02_v01_step_04", "pass",
                     "VERIFY step: User informed that the information was displayed correclty on his/her IUT",
                     ""], ["CHECK_1_post_mortem_analysis", "pass",
                           "<Frame   3: [bbbb::1 -> bbbb::2] CoAP [CON 43213] DELETE /test> Match: CoAP(type=0, code=4)"],
                    ["CHECK_2_post_mortem_analysis", "pass",
                     "<Frame   4: [bbbb::2 -> bbbb::1] CoAP [ACK 43213] 2.02 Deleted > Match: CoAP(code=66, mid=0xa8cd, tok=b'')"]]
            }
    }


###### SNIFFING SERVICES REQUEST MESSAGES ######

class MsgSniffingStart(Message):
    """
    Testing Tools'internal call.
    Coordinator -> Sniffer
    Testing Tool SHOULD implement (design recommendation)
    """

    routing_key = 'control.sniffing.service'

    _msg_data_template = {
        '_type': 'sniffing.start',
        'capture_id': 'TD_COAP_CORE_01',
        'filter_if': 'tun0',
        'filter_proto': 'udp port 5683'
    }


class MsgSniffingStartReply(MsgReply):
    """
    Testing Tools'internal call.
    Sniffer -> Coordinator
    Testing Tool SHOULD implement (design recommendation)
    """

    routing_key = 'control.sniffing.service.reply'

    _msg_data_template = {
        '_type': 'sniffing.start.reply',
        'ok': True
    }


class MsgSniffingStop(Message):
    """
    Testing Tools'internal call.
    Coordinator -> Sniffer
    Testing Tool SHOULD implement (design recommendation)
    """

    routing_key = 'control.sniffing.service'

    _msg_data_template = {
        '_type': 'sniffing.stop',
    }


class MsgSniffingStoptReply(MsgReply):
    """
    Testing Tools'internal call.
    Sniffer -> Coordinator
    Testing Tool SHOULD implement (design recommendation)
    """

    routing_key = 'control.sniffing.service.reply'

    _msg_data_template = {
        '_type': 'sniffing.stop.reply',
        'ok': True
    }


class MsgSniffingGetCapture(Message):
    """
    Testing Tools'internal call.
    Coordinator -> Sniffer
    Testing Tool SHOULD implement (design recommendation)
    """

    routing_key = 'control.sniffing.service'

    _msg_data_template = {
        '_type': 'sniffing.getcapture',
        "capture_id": "TD_COAP_CORE_01",

    }


class MsgSniffingGetCaptureReply(MsgReply):
    routing_key = 'control.sniffing.service.reply'

    _msg_data_template = {
        '_type': 'sniffing.getcapture.reply',
        'ok': True,
        'file_enc': 'pcap_base64',
        'filename': 'TD_COAP_CORE_01.pcap',
        'value': '1MOyoQIABAAAAAAAAAAAAMgAAAAAAAAA',  # empty PCAP
    }


class MsgSniffingGetCaptureLast(Message):
    """
    Testing Tools'internal call.
    Coordinator -> Sniffer
    Testing Tool SHOULD implement (design recommendation)
    """

    routing_key = 'control.sniffing.service'

    _msg_data_template = {
        '_type': 'sniffing.getlastcapture',
    }


class MsgSniffingGetCaptureLastReply(MsgReply):
    routing_key = 'control.sniffing.service.reply'

    _msg_data_template = {
        '_type': 'sniffing.getlastcapture.reply',
        'ok': True,
        'file_enc': 'pcap_base64',
        'filename': 'TD_COAP_CORE_01.pcap',
        'value': '1MOyoQIABAAAAAAAAAAAAMgAAAAAAAAA',  # empty PCAP
    }


###### ANALYSIS MESSAGES ######

class MsgInteropTestCaseAnalyze(Message):
    """
    Testing Tools'internal call.
    Coordinator -> Analyzer
    Testing Tool SHOULD implement (design recommendation)
    """

    PCAP_empty_base64 = '1MOyoQIABAAAAAAAAAAAAMgAAAAAAAAA'

    routing_key = 'control.analysis.service'

    _msg_data_template = {
        '_type': 'analysis.interop.testcase.analyze',
        "testcase_id": "TD_COAP_CORE_01",
        "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_01_v01",
        "file_enc": "pcap_base64",
        "filename": "TD_COAP_CORE_01.pcap",
        "value": PCAP_empty_base64,
    }


class MsgInteropTestCaseAnalyzeReply(MsgReply):
    """
    Testing Tools'internal call.
    Analyzer -> Coordinator
    Testing Tool SHOULD implement (design recommendation)

    The recommended structure for the partial_verdicts field is a list of partial verdicts with the following
    requirements:
     - each one of those elements of the list correspond to one CHECK or VERIFY steps of the test description
     - first value of the list MUST be a "pass", "fail", "inconclusive" or eventually "error" partial verdict (string)
     - the second value MUST be a string with a description of partial verdict (intended for the user)
     - more values elements MAY be added to the list

    """

    _msg_data_template = {
        '_type': 'analysis.interop.testcase.analyze.reply',
        'ok': True,
        'verdict': 'pass',
        'analysis_type': 'postmortem',
        'description': 'The test purpose has been verified without any fault detected',
        'review_frames': [],
        'token': '0lzzb_Bx30u8Gu-xkt1DFE1GmB4',
        "partial_verdicts": [
            [
                "pass", "<Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON 43521] GET /test> Match: CoAP(type=0, code=1)"
            ],

            [
                "pass",
                "<Frame   2: [127.0.0.1 -> 127.0.0.1] CoAP [ACK 43521] 2.05 Content > Match: CoAP(code=69, mid=0xaa01, \
                tok=b'b\\xda', pl=Not(b''))"
            ],
            [
                "pass",
                "<Frame   2: [127.0.0.1 -> 127.0.0.1] CoAP [ACK 43521] 2.05 Content > \
                Match: CoAP(opt=Opt(CoAPOptionContentFormat()))"
            ]
        ],
        "testcase_id": "TD_COAP_CORE_01",
        "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_01_v01",
    }


###### DISSECTION MESSAGES ######

class MsgDissectionDissectCapture(Message):
    """
    Testing Tools'internal call.
    Coordinator -> Dissector
    and
    Analyzer -> Dissector
    Testing Tool SHOULD implement (design recommendation)
    """

    PCAP_COAP_GET_OVER_TUN_INTERFACE_base64 = "1MOyoQIABAAAAAAAAAAAAMgAAABlAAAAqgl9WK8aBgA7AAAAOwAAAGADPxUAExFAu7s" \
                                              "AAAAAAAAAAAAAAAAAAbu7AAAAAAAAAAAAAAAAAALXvBYzABNZUEABcGO0dGVzdMECqg" \
                                              "l9WMcaBgCQAAAAkAAAAGAAAAAAaDr//oAAAAAAAAAAAAAAAAAAA7u7AAAAAAAAAAAAA" \
                                              "AAAAAGJAAcTAAAAALu7AAAAAAAAAAAAAAAAAAK7uwAAAAAAAAAAAAAAAAACBAgAAAAA" \
                                              "AABgAz8VABMRQLu7AAAAAAAAAAAAAAAAAAG7uwAAAAAAAAAAAAAAAAAC17wWMwATWVB" \
                                              "AAXBjtHRlc6oJfVjSGgYAOwAAADsAAABgAz8VABMRP7u7AAAAAAAAAAAAAAAAAAG7uw" \
                                              "AAAAAAAAAAAAAAAAAC17wWMwATWVBAAXBjtHRlc3TBAg=="

    routing_key = 'control.dissection.service'

    _msg_data_template = {
        '_type': 'dissection.dissectcapture',
        "file_enc": "pcap_base64",
        "filename": "TD_COAP_CORE_01.pcap",
        "value": PCAP_COAP_GET_OVER_TUN_INTERFACE_base64,
        "protocol_selection": 'coap',
    }


class MsgDissectionDissectCaptureReply(MsgReply):
    """
    Testing Tools'internal call.
    Dissector -> Coordinator
    and
    Dissector -> Analyzer
    Testing Tool SHOULD implement (design recommendation)
    """

    _frames_example = [
        {
            "_type": "frame",
            "id": 1,
            "timestamp": 1464858393.547275,
            "error": None,
            "protocol_stack": [
                {
                    "_type": "protocol",
                    "_protocol": "NullLoopback",
                    "AddressFamily": "2",
                    "ProtocolFamily": "0"
                },
                {
                    "_type": "protocol",
                    "_protocol": "IPv4",
                    "Version": "4",
                    "HeaderLength": "5",
                    "TypeOfService": "0x00",
                    "TotalLength": "41",
                    "Identification": "0x71ac",
                    "Reserved": "0",
                    "DontFragment": "0",
                    "MoreFragments": "0",
                    "FragmentOffset": "0",
                    "TimeToLive": "64",
                    "Protocol": "17",
                    "HeaderChecksum": "0x0000",
                    "SourceAddress": "127.0.0.1",
                    "DestinationAddress": "127.0.0.1",
                    "Options": "b''"
                }
            ]
        },
    ]

    _msg_data_template = {
        '_type': 'dissection.dissectcapture.reply',
        'ok': True,
        'token': '0lzzb_Bx30u8Gu-xkt1DFE1GmB4',
        'frames': _frames_example
    }


class MsgDissectionAutoDissect(Message):
    """
    Testing Tool's MUST-implement.
    Testing Tool -> GUI
    GUI MUST display this info during execution:
     - interop session
     - conformance session
     - performance ?
     - privacy?

    """
    routing_key = 'control.dissection.auto'

    _frames_example = MsgDissectionDissectCaptureReply._frames_example

    _msg_data_template = {
        '_type': 'dissection.autotriggered',
        'token': '0lzzb_Bx30u8Gu-xkt1DFE1GmB4',
        'frames': _frames_example
    }


message_types_dict = {
    "testcoordination.testsuite.start": MsgTestSuiteStart, # GUI -> TestingTool
    "testcoordination.testcase.ready": MsgTestCaseReady,  # TestingTool -> GUI
    "testcoordination.testcase.start": MsgTestCaseStart, # GUI -> TestingTool
    "testcoordination.step.execute": MsgStepExecute, # TestingTool -> GUI
    "testcoordination.testcase.configuration": MsgTestCaseConfiguration, # TestingTool -> GUI
    "testcoordination.testcase.stop": MsgTestCaseStop, # GUI -> TestingTool
    "testcoordination.testcase.restart": MsgTestCaseRestart, # GUI -> TestingTool
    "testcoordination.step.stimuli.executed": MsgStimuliExecuted, # GUI -> TestingTool
    "testcoordination.step.check.response": MsgCheckResponse, # GUI -> TestingTool
    "testcoordination.step.verify.response": MsgVerifyResponse, # GUI -> TestingTool
    "testcoordination.testcase.skip": MsgTestCaseSkip, # GUI -> TestingTool
    "testcoordination.testcase.select": MsgTestCaseSelect, # GUI -> TestingTool
    "testcoordination.testcase.finish": MsgTestCaseFinish, # GUI -> TestingTool
    "testcoordination.testcase.verdict": MsgTestCaseVerdict, # TestingTool -> GUI
    "testcoordination.testsuite.abort": MsgTestSuiteAbort, # GUI -> TestingTool
    "testcoordination.testsuite.getstatus": MsgTestSuiteGetStatus, # GUI -> TestingTool
    "testcoordination.testsuite.getstatus.reply": MsgTestSuiteGetStatusReply,# TestingTool -> GUI (reply)
    "testcoordination.testsuite.gettestcases": MsgTestSuiteGetTestCases,# GUI -> TestingTool
    "testcoordination.testsuite.gettestcases.reply": MsgTestSuiteGetTestCasesReply,# TestingTool -> GUI (reply)
    "testcoordination.testsuite.report" : MsgTestSuiteReport, # TestingTool -> GUI
    "sniffing.start": MsgSniffingStart, # Testing Tool Internal
    "sniffing.stop": MsgSniffingStop, # Testing Tool Internal
    "sniffing.getcapture": MsgSniffingGetCapture,  # Testing Tool Internal
    "sniffing.getlastcapture": MsgSniffingGetCaptureLast,  # Testing Tool Internal
    "analysis.interop.testcase.analyze": MsgInteropTestCaseAnalyze,  # Testing Tool Internal
    "analysis.interop.testcase.analyze.reply": MsgInteropTestCaseAnalyzeReply,  # Testing Tool Internal
    "dissection.dissectcapture": MsgDissectionDissectCapture,  # Testing Tool Internal
    "dissection.dissectcapture.reply": MsgDissectionDissectCaptureReply,  # Testing Tool Internal
    "session.terminate": MsgSessionTerminate, # GUI (or Orchestrator?) -> TestingTool
    "control.dissection.auto": MsgDissectionAutoDissect, # TestingTool -> GUI
}

if __name__ == '__main__':
    # m1=MsgTestCaseStart()
    # print(json.dumps(m1.to_dict()))
    # print(m1.routing_key)
    # print(m1.to_json())
    # print(m1)

    m1 = MsgTestCaseStart(hola='verano')
    m2 = MsgTestCaseStart()
    # m2 = MsgTestCaseStart(routing_key = 'lolo', hola='verano')

    print(m1)
    print(m1._msg_data)
    j = m1.to_json()
    print(j)
    deco = Message.from_json(j)
    print(repr(deco))

    print(m2)
    print(m2.to_json())
    print(m2._msg_data)

    m2 = MsgTestSuiteStart()
    print(json.dumps(m2.to_dict()))
    print(m2.routing_key)
    print(m2.to_json())
    print(m2)

    m3 = MsgTestCaseStop()
    print(json.dumps(m3.to_dict()))
    print(m3.routing_key)
    print(m3.to_json())
    print(m3)

    j = json.dumps({
        '_type': 'dissection.dissectcapture',
        "file_enc": "pcap_base64",
        "filename": "TD_COAP_CORE_01.pcap",
        "protocol_selection": 'coap',
    })
    r = Message.from_json(j)
    print(type(r))
    print(r)

    m = MsgTestCaseSkip()
    print(m)
    print(
            m.routing_key,
            m.message_id,
            m.testcase_id,
    )
    m = MsgTestCaseSkip(testcase_id='TD_COAP_CORE_03_v01')
    print(
            m.testcase_id,
            m.to_json(),
    )
    m = MsgTestSuiteStart()
    m.to_json()
    json_message = m.to_json()
    obj = Message.from_json(json_message)
    type(obj)

    # build responses from requests
    m = MsgSniffingStart()
    err = MsgErrorReply(m)
    print(
            err,
            m.reply_to,
            err.routing_key,
            m.message_id,
            m.correlation_id,
    )

    import doctest

    doctest.testmod()
