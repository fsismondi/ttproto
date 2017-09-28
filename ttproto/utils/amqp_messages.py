# -*- coding: utf-8 -*-

"""

About the library:
-----------------

This module provides the API message formats used in F-Interop.

The idea is to be able to have an
- organized and centralized way of dealing with the big amount of messages formats used in the platform;
- to be able to import (or just copy/paste) these messages formats from any component in the F-Interop platform,
- re-use this also for the integration testing;
- to have version control the messages e.g. messages_testcase_start API v1 and API v2;
- to have a direct way of exporting this as doc.


F-Interop conventions:
---------------------
- if event is a service request then the routing key (r_key) is control.someFunctionality.service
- a reply to a service will be on topic/r_key : control.someFunctionality.service.reply
- reply.correlation_id = request.correlation_id


Usage:
------
>>> from messages import * # doctest: +SKIP
>>> m = MsgTestCaseSkip()
>>> m
MsgTestCaseSkip(_api_version = 0.1.43, _type = testcoordination.testcase.skip, node = someNode, testcase_id = TD_COAP_CORE_02_v01, )
>>> m.routing_key
'control.testcoordination'
>>> m.message_id # doctest: +SKIP
'802012eb-24e3-45c4-9dcc-dc293c584f63'
>>> m.testcase_id
'TD_COAP_CORE_02_v01'

# also we can modify some of the fields (rewrite the default ones)
>>> m = MsgTestCaseSkip(testcase_id = 'TD_COAP_CORE_03_v01')
>>> m
MsgTestCaseSkip(_api_version = 0.1.43, _type = testcoordination.testcase.skip, node = someNode, testcase_id = TD_COAP_CORE_03_v01, )
>>> m.testcase_id
'TD_COAP_CORE_03_v01'

# and even export the message in json format (for example for sending the message though the amqp event bus)
>>> m.to_json()
'{"_api_version": "0.1.43", "_type": "testcoordination.testcase.skip", "node": "someNode", "testcase_id": "TD_COAP_CORE_03_v01"}'

# We can use the Message class to import json into Message objects:
>>> m=MsgTestSuiteStart()
>>> m.to_json()
'{"_api_version": "0.1.43", "_type": "testcoordination.testsuite.start", "description": "Event test suite START"}'
>>> json_message = m.to_json()
>>> obj=Message.from_json(json_message)
>>> type(obj)
<class 'messages.MsgTestSuiteStart'>

# We can use the library for generating error responses:
# the request:
>>> m = MsgSniffingStart()
>>>
# the error reply (note that we pass the message of the request to build the reply):
>>> err = MsgErrorReply(m)
>>> err
MsgErrorReply(_api_version = 0.1.43, _type = sniffing.start, error_code = Some error code TBD, error_message = Some error message TBD, ok = False, )
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
import time
import json
import uuid

API_VERSION = '0.1.43'


# TODO use metaclasses instead?
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
            content_type="application/json",
            message_id=str(uuid.uuid4()),
            timestamp=int(time.time())
        )

        try:
            if self.routing_key.endswith(".service"):
                self._properties["reply_to"] = "%s.%s" % (self.routing_key, "reply")
                self._properties["correlation_id"] = self._properties["message_id"]
        except AttributeError:
            pass

        # rewrite default data fields with the passed args
        self._msg_data.update(kwargs)

        # add API's version
        self._msg_data["_api_version"] = API_VERSION

        # add values as objects attributes
        for key in self._msg_data:
            setattr(self, key, self._msg_data[key])

        # add props as objects attributes
        for key in self._properties:
            setattr(self, key, self._properties[key])

    def to_dict(self):
        resp = {}
        # let's use sorted so API returns items inside always in the same order
        for field in sorted(self._msg_data.keys()):
            resp[field] = getattr(self, field)

        return OrderedDict(sorted(resp.items(), key=lambda t: t[0]))  # sorted by key

    def to_json(self):
        return json.dumps(self.to_dict())

    def get_properties(self):
        resp = OrderedDict()
        for field in self._properties:
            resp[field] = getattr(self, field)
        return resp

    def __str__(self):
        s = " - " * 20 + "\n"
        s += "Message routing key: %s" % self.routing_key
        s += "\n -  -  - \n"
        s += "Message properties: %s" % json.dumps(self.get_properties(), indent=4, )
        s += "\n -  -  - \n"
        s += "Message body: %s" % json.dumps(self.to_dict(), indent=4, )
        s += "\n" + " - " * 20
        return s

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
            message_dict = json.loads(body.decode("utf-8"))
        else:
            raise NonCompliantMessageFormatError("Not a Json")

        # check fist if it's a response
        if "ok" in message_dict:
            # cannot build a complete reply message just from the json representation
            return

        return cls.from_dict(message_dict)

    @classmethod
    def from_dict(cls, message_dict):
        """
        :param body: dict
        :return:  Message object generated from the body
        :raises NonCompliantMessageFormatError: If the message cannot be build from the provided json
        """
        assert type(message_dict) is dict

        # check fist if it's a response
        if "ok" in message_dict:
            # cannot build a complete reply message just from the json representation
            return

        message_type = message_dict["_type"]

        if message_type in message_types_dict:
            return message_types_dict[message_type](**message_dict)
        else:
            raise NonCompliantMessageFormatError("Cannot load json message: %s" % str(message_dict))

    def __repr__(self):
        ret = "%s(" % self.__class__.__name__
        for key, value in self.to_dict().items():
            ret += "%s = %s, " % (key, value)
        ret += ")"
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
        if not hasattr(self, "_msg_data_template"):
            self._msg_data_template = {
                "_type": request_message._type,
                "ok": True,
            }

        super(MsgReply, self).__init__(**kwargs)

        # overwrite correlation id template and attribute
        self._properties["correlation_id"] = request_message.correlation_id
        self.correlation_id = request_message.correlation_id


class MsgErrorReply(MsgReply):
    """
    see section "F-Interop conventions" on top
    """

    def __init__(self, request_message, **kwargs):
        assert request_message
        # msg_data_template doesnt include _type cause this class is generic, we can only get this at init from request
        # so, let's copy the _type from request and let the MsgReply handle the rest of the fields
        self._msg_data_template["_type"] = request_message._type
        super(MsgErrorReply, self).__init__(request_message, **kwargs)

    _msg_data_template = {
        "ok": False,
        "error_message": "Some error message TBD",
        "error_code": "Some error code TBD"
    }


# # # # # # AGENT MESSAGES # # # # # #

class MsgAgentTunStart(Message):
    """
    Requirements: Testing Tool MAY implement (if IP tun needed)

    Type: Event

    Pub/Sub: Testing Tool -> Agent

    Description: Message for triggering start IP tun interface in OS where the agent is running
    """
    routing_key = "control.tun.toAgent.agent_TT"

    _msg_data_template = {
        "_type": "tun.start",
        "name": "agent_TT",
        "ipv6_prefix": "bbbb",
        "ipv6_host": ":3",
        "ipv6_no_forwarding": False,
        "ipv4_host": None,
        "ipv4_network": None,
        "ipv4_netmask": None,
    }


class MsgAgentSerialStarted(Message):
    """
    Description: Message for indicating that agent serial interface has been started

    Type: Event

    Pub/Sub: Testing Tool -> Agent

    Description: TBD
    """
    routing_key = "control.serial.from.tbd"

    _msg_data_template = {
        "_type": "serial.started",
        "name": "tbd",
        "port": "tbd",
        "boudrate": "tbd",
    }


class MsgAgentTunStarted(Message):
    """
    Description: Message for indicating that agent tun has been started

    Type: Event

    Pub/Sub: Agent -> Testing Tool

    Description: TBD
    """
    routing_key = "control.tun.from.tbd"

    _msg_data_template = {
        "_type": "tun.started",
        "name": "agent_TT",
        "ipv6_prefix": "bbbb",
        "ipv6_host": ":3",
        "ipv4_host": None,
        "ipv4_network": None,
        "ipv4_netmask": None,
        "ipv6_no_forwarding": False,
    }


class MsgPacketInjectRaw(Message):
    """
    Description: Message to be captured by the agent an push into the correct embedded interface (e.g. tun, serial, etc..)

    Type: Event

    Pub/Sub: Testing Tool -> Agent

    Description: TBD
    """
    routing_key = None  # depends on the agent_id and the agent interface being used, re-write after creation

    _msg_data_template = {
        "_type": "packet.to_inject.raw",
        "timestamp": "1488586183.45",
        "interface_name": "tun0",
        "data": [96, 0, 0, 0, 0, 36, 0, 1, 254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 255, 2, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 22, 58, 0, 5, 2, 0, 0, 1, 0, 143, 0, 112, 7, 0, 0, 0, 1, 4, 0, 0, 0, 255, 2, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]}


class MsgPacketSniffedRaw(Message):
    """
    Description: Message captured by the agent in one of its embedded interfaces (e.g. tun, serial, etc..)

    Type: Event

    Pub/Sub: Agent -> Testing Tool

    Description: TBD
    """
    routing_key = None  # depends on the agent_id and the agent interface being used, re-write after creation

    _msg_data_template = {
        "_type": "packet.sniffed.raw",
        "timestamp": "1488586183.45",
        "interface_name": "tun0",
        "data": [96, 0, 0, 0, 0, 36, 0, 1, 254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 255, 2, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 22, 58, 0, 5, 2, 0, 0, 1, 0, 143, 0, 112, 7, 0, 0, 0, 1, 4, 0, 0, 0, 255, 2, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]}


# # # # # # SESSION MESSAGES # # # # # #

class MsgTestingToolTerminate(Message):
    """
    Requirements: Testing Tool MUST listen to event

    Type: Event

    Pub/Sub: GUI, (or Orchestrator) -> Testing Tool

    Description: Testing tool should stop all it's processes gracefully.
    """
    routing_key = "control.session"

    _msg_data_template = {
        "_type": "testingtool.terminate",
        "description": "Event TERMINATE testing tool execution"
    }


class MsgTestingToolReady(Message):
    """
    Requirements: Testing Tool MUST publish event

    Type: Event

    Typcal_use: Testing Tool -> GUI

    Description: Used to indicate to the GUI that testing is ready to start the test suite
    """
    routing_key = "control.session"

    _msg_data_template = {
        "_type": "testingtool.ready",
        "description": "Event Testing tool READY to start test suite."
    }


class MsgTestingToolComponentReady(Message):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Event

    Pub/Sub: Any Testing tool's component -> Test Coordinator

    Description: Once a testing tool's component is ready, it should publish a compoennt ready message
    """
    routing_key = "control.session"

    _msg_data_template = {
        "_type": "testingtool.component.ready",
        "component": "SomeComponent",
        "description": "Component READY to start test suite."
    }


class MsgSessionChat(Message):
    """
    Requirements: GUI should implement

    Type: Event

    Pub/Sub: UI 1 (2) -> UI 2 (1)

    Description: Generic descriptor of chat messages
    """
    routing_key = "log.warning.the_drummer"

    _msg_data_template = {
        "_type": "chat",
        "user_name": "Ringo",
        "iut_node": "tbd",
        "description": "I've got blisters on my fingers!"
    }


class MsgSessionLog(Message):
    """
    Requirements: Testing Tool SHOULD implement

    Type: Event

    Pub/Sub: Any Testing tool's component -> user/devs interfaces

    Description: Generic descriptor of log messages
    """
    routing_key = "log.warning.the_drummer"

    _msg_data_template = {
        "_type": "log",
        "component": "misc",
        "message": "I've got blisters on my fingers!"
    }


# TODO delete "Interop" to generalize

class MsgInteropSessionConfiguration(Message):
    """
    Requirements: Testing Tool MUST listen to event

    Type: Event

    Pub/Sub: Orchestrator -> Testing Tool

    Description: Testing tool MUST listen to this message and configure the testsuite correspondingly
    """
    routing_key = "control.session"

    _msg_data_template = {
        "_type": "session.interop.configuration",
        "session_id": "TBD",
        "testing_tools": "f-interop/interoperability-coap",
        "users": [
            "u1",
            "f-interop"
        ],
        "iuts": [
            {
                "id": "someImplementationFromAUser",
                "role": "coap_server",
                "execution_mode": "user-assisted",
                "location": "user-facilities",
                "owner": "someUserName",
                "version": "0.1"
            },
            {
                "id": "automated_iut-coap_client-coapthon-v0.1",
                "role": "coap_client",
                "execution_mode": "automated-iut",
                "location": "central-server-docker",
                "owner": "f-interop",
                "version": "0.1"
            }
        ],
        "tests": [
            {
                "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_01_v01",
                "settings": {}
            },
            {
                "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_02_v01",
                "settings": {}
            },
            {
                "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_03_v01",
                "settings": {}
            }
        ]
    }


class MsgAgentConfigured(Message):
    """
    Requirements: Testing Tool SHOULD publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description: The goal is to notify GUI when agents are ready to start the session
    """

    routing_key = "control.session"

    _msg_data_template = {
        "_type": "agent.configured",
        "description": "Event agent successfully CONFIGURED",
        'name': 'agent_TT'
    }


class MsgTestingToolConfigured(Message):
    """
    Requirements: Testing Tool MUST publish event

    Type: Event

    Pub/Sub: Testing Tool -> Orchestrator, GUI

    Description: The goal is to notify orchestrator and other components that the testing tool has been configured
    """

    routing_key = "control.session"

    _msg_data_template = {
        "_type": "testingtool.configured",
        "description": "Event Testing tool CONFIGURED",
        "session_id": "TBD",
        "testing_tools": "f-interop/interoperability-coap",
    }


class MsgSessionCreated(Message):
    """
    Requirements: Session Orchestrator MUST publish message on common-services channel (on every session creation)

    Type: Event

    Pub/Sub: SO -> viz tools

    Description: The goal is to notify viz tools about new sessions
    """

    routing_key = "control.session.created"

    _msg_data_template = {
        "_type": "session.created",
        "description": "A new session has been created",
        "session_id": "TBD",
        "testing_tools": "TBD",
    }


class MsgTestingToolComponentShutdown(Message):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Event

    Pub/Sub: Any Testing tool's component -> Test Coordinator

    Description: tbd
    """
    routing_key = "control.session"

    _msg_data_template = {
        "_type": "testingtool.component.shutdown",
        "component": "SomeComponent",
        "description": "Event Component SHUTDOWN. Bye!"
    }

    # # # # # # TEST COORDINATION MESSAGES # # # # # #


class MsgTestSuiteStart(Message):
    """
    Requirements: Testing Tool MUST listen to event

    Type: Event

    Pub/Sub: GUI -> Testing Tool

    Description: tbd
    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.testsuite.start",
        "description": "Event test suite START"
    }


class MsgTestSuiteFinish(Message):
    """
    Requirements: Testing Tool MUST listen to event

    Type: Event

    Pub/Sub: GUI -> Testing Tool

    Description: tbd
    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.testsuite.finish",
        "description": "Event test suite FINISH"
    }


class MsgTestCaseReady(Message):
    """
    Requirements: Testing Tool MUST publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description:
        - Used to indicate to the GUI (or automated-iut) which is the next test case to be executed.
        - This message is normally followed by a MsgTestCaseStart (from GUI-> Testing Tool)
    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.testcase.ready",
        "description": "Next test case to be executed is TD_COAP_CORE_01_v01",
        "testcase_id": "TD_COAP_CORE_01_v01",
        "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_01_v01",
        "objective": "Perform GET transaction(CON mode)",
        "state": None
    }


class MsgTestCaseStart(Message):
    """
    Requirements: Testing Tool MUST listen to event

    Type: Event

    Pub/Sub: GUI -> Testing Tool

    Description:
        - Message used for indicating the testing tool to start the test case (the one previously selected)
        - if testcase_id is Null then testing tool starts previously announced testcase in message
        "testcoordination.testcase.ready",
    """
    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.testcase.start",
        "description": "Event test case START",
        "testcase_id": "TBD",
    }


class MsgTestCaseStarted(Message):
    """
    Requirements: Testing Tool SHOULD publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description:
        - Message used for indicating that testcase has started
    """
    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.testcase.started",
        "description": "Event test case STARTED",
        "testcase_id": "TBD",
    }


# TODO MsgTestCaseNotes, see https://portal.etsi.org/cti/downloads/TestSpecifications/6LoWPAN_Plugtests_TestDescriptions_1.0.pdf


class MsgTestCaseConfiguration(Message):
    """
    Requirements: Testing Tool MAY publish event (if needed for executing the test case)
    Type: Event
    Pub/Sub: Testing Tool -> GUI & automated-iut
    Description:
        - Message used to indicate GUI and/or automated-iut which configuration to use.
        - IMPORTANT: deprecate this message in favor of MsgConfigurationExecute and MsgConfigurationExecuted
    """
    routing_key = "control.testcoordination"
    _msg_data_template = {
        "_type": "testcoordination.testcase.configuration",
        "configuration_id": "COAP_CFG_01_v01",
        "node": "coap_server",
        "testcase_id": "TBD",
        "testcase_ref": "TBD",
        "description":
            ["CoAP servers running service at [bbbb::2]:5683",
             "CoAP servers are requested to offer the following resources",
             ["/test", "Default test resource", "Should not exceed 64bytes"],
             ["/seg1/seg2/seg3", "Long path ressource", "Should not exceed 64bytes"],
             ["/query", "Ressource accepting query parameters", "Should not exceed 64bytes"],
             ["/separate",
              "Ressource which cannot be served immediately and which cannot be "
              "acknowledged in a piggy-backed way",
              "Should not exceed 64bytes"],
             ["/large", "Large resource (>1024 bytes)", "shall not exceed 2048bytes"],
             ["/large_update",
              "Large resource that can be updated using PUT method (>1024 bytes)",
              "shall not exceed 2048bytes"],
             ["/large_create",
              "Large resource that can be  created using POST method (>1024 bytes)",
              "shall not exceed 2048bytes"],
             ["/obs", "Observable resource which changes every 5 seconds",
              "shall not exceed 2048bytes"],
             ["/.well-known/core", "CoRE Link Format", "may require usage of Block options"]
             ]
    }


class MsgConfigurationExecute(Message):
    """
    Requirements: Testing Tool MAY publish event (if needed for executing the test case)

    Type: Event

    Pub/Sub: Testing Tool -> GUI & automated-iut

    Description:
        - Message used to indicate GUI and/or automated-iut which configuration to use.
    """
    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.configuration.execute",
        "configuration_id": "COAP_CFG_01_v01",
        "node": "coap_server",
        "testcase_id": "TBD",
        "testcase_ref": "TBD",
        "description":
            ["CoAP servers running service at [bbbb::2]:5683",
             "CoAP servers are requested to offer the following resources",
             ["/test", "Default test resource", "Should not exceed 64bytes"],
             ["/seg1/seg2/seg3", "Long path ressource", "Should not exceed 64bytes"],
             ["/query", "Ressource accepting query parameters", "Should not exceed 64bytes"],
             ["/separate",
              "Ressource which cannot be served immediately and which cannot be "
              "acknowledged in a piggy-backed way",
              "Should not exceed 64bytes"],
             ["/large", "Large resource (>1024 bytes)", "shall not exceed 2048bytes"],
             ["/large_update",
              "Large resource that can be updated using PUT method (>1024 bytes)",
              "shall not exceed 2048bytes"],
             ["/large_create",
              "Large resource that can be  created using POST method (>1024 bytes)",
              "shall not exceed 2048bytes"],
             ["/obs", "Observable resource which changes every 5 seconds",
              "shall not exceed 2048bytes"],
             ["/.well-known/core", "CoRE Link Format", "may require usage of Block options"]
             ]
    }


class MsgConfigurationExecuted(Message):
    """
    Requirements: Testing Tool SHOULD listen to event

    Type: Event

    Pub/Sub: GUI (automated-IUT) -> Testing Tool

    Description:
        - Message used for indicating that the IUT has been configured as requested
        - pixit must be included in this message (pixit = Protocol Implementaiton eXtra Information for Testing)
    """
    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.configuration.executed",
        "description": "Event IUT has been configured",
        "node": "coap_server",
        "ipv6_address": "tbd"  # example of pixit
    }


class MsgTestCaseStop(Message):
    """
    Requirements: Testing Tool MUST listen to event

    Type: Event

    Pub/Sub: GUI & automated-iut -> Testing Tool

    Description:
        - Message used for indicating the testing tool to stop the test case (the one running).
    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.testcase.stop",
        "description": "Event test case STOP"
    }


class MsgTestCaseRestart(Message):
    """
    Requirements: Testing Tool MUST listen to event

    Type: Event

    Pub/Sub: GUI -> Testing Tool

    Description: Restart the running test cases.
    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.testcase.restart",
        "description": "Event test case RESTART"
    }


class MsgStepStimuliExecute(Message):
    """
    Requirements: Testing Tool MUST publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description:
        - Used to indicate to the GUI (or automated-iut) which is the stimuli step to be executed by the user (or
        automated-IUT).
    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.step.stimuli.execute",
        "description": "Please execute TD_COAP_CORE_01_v01_step_01",
        "step_id": "TD_COAP_CORE_01_v01_step_01",
        "step_type": "stimuli",
        "step_info": [
            "Client is requested to send a GET request with",
            "Type = 0(CON)",
            "Code = 1(GET)"
        ],
        "step_state": "executing",
        "node": "coap_client",
        "node_execution_mode": "user_assisted",
        "testcase_id": "TBD",
        "testcase_ref": "TBD",
        "target_address": "TBD"
    }


class MsgStepStimuliExecuted(Message):
    """
    Requirements: Testing Tool MUST listen to event

    Type: Event

    Pub/Sub: GUI (or automated-IUT)-> Testing Tool

    Description:
        - Used to indicate stimuli has been executed by user (and it's user-assisted iut) or by automated-iut
    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.step.stimuli.executed",
        "description": "Event step (stimuli) EXECUTED",
        "node": "coap_client",
        "node_execution_mode": "user_assisted",
    }


class MsgStepCheckExecute(Message):
    """
    Requirements: Testing Tool SHOULD publish event

    Type: Event

    Pub/Sub: Testing Tool -> Analysis

    Description:
        - Used to indicate to the GUI (or automated-iut) which is the stimuli step to be executed by the user (or
        automated-IUT).
    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.step.check.execute",
        "description": "Please execute TD_COAP_CORE_01_v01_step_02",
        "step_id": "TD_COAP_CORE_01_v01_step_02",
        "step_type": "check",
        "step_info": [
            "The request sent by the client contains",
            "Type=0 and Code=1,"
            "Client-generated Message ID (➔ CMID)",
            "Client-generated Token (➔ CTOK)",
            "UTEST Uri-Path option test"
        ],
        "step_state": "executing",
        "testcase_id": "TBD",
        "testcase_ref": "TBD"
    }


class MsgStepCheckExecuted(Message):
    """
    Requirements: Testing Tool SHOULD implement

    Type: Event

    Pub/Sub: test coordination -> test analysis

    Description:
        - In the context of IUT to IUT test execution, this message is used for indicating that the previously
        executed
        messages (stimuli message and its reply) CHECK or comply to what is described in the Test Description.
        - Not used in CoAP testing Tool (analysis of traces is done post mortem)
    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.step.check.executed",
        "partial_verdict": "pass",
        "description": "TAT says: step complies (checks) with specification",
    }


class MsgStepVerifyExecute(Message):
    """
    Requirements: Testing Tool MUST publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI (or automated-IUT)

    Description:
        - Used to indicate to the GUI (or automated-iut) which is the verify step to be executed by the user (or
        automated-IUT).
    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.step.verify.execute",
        "response_type": "bool",
        "description": "Please execute TD_COAP_CORE_01_v01_step_04",
        "step_id": "TD_COAP_CORE_01_v01_step_04",
        "step_type": "verify",
        "step_info": [
            "Client displays the received information"
        ],
        "node": "coap_client",
        "node_execution_mode": "user_assisted",
        "step_state": "executing",
        "testcase_id": "TBD",
        "testcase_ref": "TBD"

    }


class MsgStepVerifyExecuted(Message):
    """
    Requirements: Testing Tool MUST listen to event

    Type: Event

    Pub/Sub: GUI (or automated-IUT)-> Testing Tool

    Description:
        - Message generated by user (GUI or automated-IUT) declaring if the IUT VERIFY verifies the expected behaviour.
    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.step.verify.executed",
        "description": "Event step (verify) EXECUTED",
        "response_type": "bool",
        "verify_response": True,
        "node": "coap_client",
        "node_execution_mode": "user_assisted",
    }

    # class MsgTestCaseFinish(Message):
    #     """
    #     TODO: TBD if needed or not
    #
    #     Requirements: Testing Tool MAY listen to event
    #     Type: Event
    #     Pub/Sub: GUI (or automated-IUT)-> Testing Tool
    #     Description:
    #         - Used for indicating that the test case has finished.
    #         - Test coordinator deduces it automatically by using the testcase's step sequence
    #         - Not used in CoAP Testing Tool.
    #     """
    #
    #     routing_key = "control.testcoordination"
    #
    #     _msg_data_template = {
    #         "_type": "testcoordination.testcase.finish",
    #     }


class MsgTestCaseFinished(Message):
    """
    Requirements: Testing Tool MUST publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description:
        - Used for indicating to subscribers that the test cases has finished.
        - This message is followed by a verdict.
    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.testcase.finished",
        "testcase_id": "TD_COAP_CORE_01",
        "testcase_ref": "TBD",
        "description": "Testcase finished"
    }


class MsgTestCaseSkip(Message):
    """
    Requirements: Testing Tool MUST listen to event

    Type: Event

    Pub/Sub: GUI (or automated-IUT)-> Testing Tool

    Description:
        - Used for skipping a test cases event when was previusly selected to be executed.
        - testcase_id (optional) : if not provided then current tc is skipped
        - node (mandatory): node requesting to skip test case
    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.testcase.skip",
        "description": "Skip testcase",
        "testcase_id": None,
        "node": "someNode",
    }


class MsgTestCaseSelect(Message):
    """
    Requirements: Testing Tool MUST listen to event

    Type: Event

    Pub/Sub: GUI (or automated-IUT)-> Testing Tool

    Description: tbd

    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.testcase.select",
        "testcase_id": "TD_COAP_CORE_03_v01",
    }


class MsgTestSuiteAbort(Message):
    """
    Requirements: Testing Tool MUST listen to event

    Type: Event

    Pub/Sub: GUI (or automated-IUT)-> Testing Tool

    Description: Event test suite ABORT
    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.testsuite.abort",
        "description": "Event test suite ABORT"
    }


class MsgTestSuiteGetStatus(Message):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Request (service)

    Pub/Sub: GUI -> Testing Tool

    Description:
        - Describes current state of the test suite.
        - Format for the response not standardised.
    """

    routing_key = "control.testcoordination.service"

    _msg_data_template = {
        "_type": "testcoordination.testsuite.getstatus",
    }


class MsgTestSuiteGetStatusReply(MsgReply):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Reply (service)

    Pub/Sub: Testing Tool -> GUI

    Description:
        - Describes current state of the test suite.
        - Format for the response not standardised.
    """

    routing_key = "control.testcoordination.service.reply"

    _msg_data_template = {
        "_type": "testcoordination.testsuite.getstatus.reply",
        "ok": True,
        "started": True,
        "testcase_id": "TD_COAP_CORE_01_v01",
        "testcase_state": "executing",
        "step_id": "TD_COAP_CORE_01_v01_step_01"

    }


class MsgTestSuiteGetTestCases(Message):
    """
    Requirements: Testing Tool SHOULD (MUST?) implement (other components should not subscribe to event)

    Type: Request (service)

    Pub/Sub: GUI -> Testing Tool

    Description: TBD
    """

    routing_key = "control.testcoordination.service"

    _msg_data_template = {
        "_type": "testcoordination.testsuite.gettestcases",
    }


class MsgTestSuiteGetTestCasesReply(MsgReply):
    """
    Requirements: Testing Tool SHOULD (MUST?) implement (other components should not subscribe to event)

    Type: Reply (service)

    Pub/Sub: Testing Tool -> GUI

    Description: TBD
    """

    routing_key = "control.testcoordination.service.reply"

    _msg_data_template = {
        "_type": "testcoordination.testsuite.gettestcases.reply",
        "ok": True,
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
    Requirements: Testing Tool MUST publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description: Used to indicate to the GUI (or automated-iut) which is the final verdict of the testcase.
    """

    routing_key = "control.testcoordination"

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
             "<Frame   4: [bbbb::2 -> bbbb::1] CoAP [ACK 43211] 2.05 Content > Match: CoAP(code=69, "
             "mid=0xa8cb, tok=b'', pl=Not(b''))"],
            ["CHECK_3_post_mortem_analysis", "pass",
             "<Frame   4: [bbbb::2 -> bbbb::1] CoAP [ACK 43211] 2.05 Content > Match: CoAP(opt=Opt("
             "CoAPOptionContentFormat()))"]],
        "testcase_id": "TD_COAP_CORE_01_v01",
        "testcase_ref": "http://f-interop.paris.inria.fr/tests/TD_COAP_CORE_01_v01",
        "objective": "Perform GET transaction(CON mode)", "state": "finished"
    }


class MsgTestSuiteReport(Message):
    """
    Requirements: Testing Tool MUST publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description: Used to indicate to the GUI (or automated-iut) the final results of the test session.
    """

    routing_key = "control.testcoordination"

    _msg_data_template = {
        "_type": "testcoordination.testsuite.report",
        "TD_COAP_CORE_01_v01":
            {
                "verdict": "pass",
                "description": "No interoperability error was detected,",
                "partial_verdicts":
                    [
                        ["TD_COAP_CORE_01_v01_step_02", None, "CHECK postponed", ""],
                        ["TD_COAP_CORE_01_v01_step_03", None, "CHECK postponed", ""],
                        ["TD_COAP_CORE_01_v01_step_04", "pass",
                         "VERIFY step: User informed that the information was displayed "
                         "correclty on his/her IUT",
                         ""],
                        ["CHECK_1_post_mortem_analysis", "pass",
                         "<Frame   3: [bbbb::1 -> bbbb::2] CoAP [CON 43211] GET /test> Match: "
                         "CoAP(type=0, code=1)"],
                        ["CHECK_2_post_mortem_analysis", "pass",
                         "<Frame   4: [bbbb::2 -> bbbb::1] CoAP [ACK 43211] 2.05 Content > "
                         "Match: CoAP(code=69, mid=0xa8cb, tok=b'', pl=Not(b''))"],
                        [
                            "CHECK_3_post_mortem_analysis",
                            "pass",
                            "<Frame   4: [bbbb::2 -> bbbb::1] CoAP [ACK 43211] 2.05 Content > "
                            "Match: CoAP(opt=Opt(CoAPOptionContentFormat()))"]
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
                     "VERIFY step: User informed that the information was displayed correclty on his/her "
                     "IUT",
                     ""], ["CHECK_1_post_mortem_analysis", "pass",
                           "<Frame   3: [bbbb::1 -> bbbb::2] CoAP [CON 43213] DELETE /test> Match: CoAP(type=0, "
                           "code=4)"],
                    ["CHECK_2_post_mortem_analysis", "pass",
                     "<Frame   4: [bbbb::2 -> bbbb::1] CoAP [ACK 43213] 2.02 Deleted > Match: CoAP("
                     "code=66, mid=0xa8cd, tok=b'')"]]
            }
    }

    # # # # # # SNIFFING SERVICES REQUEST MESSAGES # # # # # #


class MsgSniffingStart(Message):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Request (service)

    Pub/Sub: coordination -> sniffing

    Description: tbd
    """

    routing_key = "control.sniffing.service"

    _msg_data_template = {
        "_type": "sniffing.start",
        "capture_id": "TD_COAP_CORE_01",
        "filter_if": "tun0",
        "filter_proto": "udp"
    }


class MsgSniffingStartReply(MsgReply):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)
    Type: Reply (service)
    Pub/Sub: sniffing -> coordination
    Description: tbd
    """

    routing_key = "control.sniffing.service.reply"

    _msg_data_template = {
        "_type": "sniffing.start.reply",
        "ok": True
    }


class MsgSniffingStop(Message):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Request (service)

    Pub/Sub: coordination -> sniffing

    Description: tbd
    """

    routing_key = "control.sniffing.service"

    _msg_data_template = {
        "_type": "sniffing.stop",
    }


class MsgSniffingStoptReply(MsgReply):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Reply (service)

    Pub/Sub: sniffing -> coordination

    Description: tbd
    """

    routing_key = "control.sniffing.service.reply"

    _msg_data_template = {
        "_type": "sniffing.stop.reply",
        "ok": True
    }


class MsgSniffingGetCapture(Message):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Request (service)

    Pub/Sub: coordination -> sniffing

    Description: tbd
    """

    routing_key = "control.sniffing.service"

    _msg_data_template = {
        "_type": "sniffing.getcapture",
        "capture_id": "TD_COAP_CORE_01",

    }


class MsgSniffingGetCaptureReply(MsgReply):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Reply (service)

    Pub/Sub: sniffing -> coordination

    Description: tbd
    """
    routing_key = "control.sniffing.service.reply"

    _msg_data_template = {
        "_type": "sniffing.getcapture.reply",
        "ok": True,
        "file_enc": "pcap_base64",
        "filename": "TD_COAP_CORE_01.pcap",
        "value": "1MOyoQIABAAAAAAAAAAAAMgAAAAAAAAA",  # empty PCAP
    }


class MsgSniffingGetCaptureLast(Message):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Request (service)

    Pub/Sub: coordination -> sniffing

    Description: tbd
    """

    routing_key = "control.sniffing.service"

    _msg_data_template = {
        "_type": "sniffing.getlastcapture",
    }


class MsgSniffingGetCaptureLastReply(MsgReply):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Reply (service)

    Pub/Sub: sniffing -> coordination

    Description: tbd
    """
    routing_key = "control.sniffing.service.reply"

    _msg_data_template = {
        "_type": "sniffing.getlastcapture.reply",
        "ok": True,
        "file_enc": "pcap_base64",
        "filename": "TD_COAP_CORE_01.pcap",
        "value": "1MOyoQIABAAAAAAAAAAAAMgAAAAAAAAA",  # empty PCAP
    }

    # # # # # # ANALYSIS MESSAGES # # # # # #


class MsgInteropTestCaseAnalyze(Message):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Request (service)

    Pub/Sub: coordination -> analysis

    Description:
        - Method to launch an analysis from a pcap file or a token if the pcap file has already been provided.
        - The method need a token or a pcap_file but doesn't allow someone to provide both.

    """

    PCAP_empty_base64 = "1MOyoQIABAAAAAAAAAAAAMgAAAAAAAAA"

    routing_key = "control.analysis.service"

    _msg_data_template = {
        "_type": "analysis.interop.testcase.analyze",
        "protocol": "coap",
        "testcase_id": "TD_COAP_CORE_01",
        "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_01_v01",
        "file_enc": "pcap_base64",
        "filename": "TD_COAP_CORE_01.pcap",
        "value": PCAP_empty_base64,
    }


class MsgInteropTestCaseAnalyzeReply(MsgReply):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Reply (service)

    Pub/Sub: analysis -> coordination

    Description:
        - The recommended structure for the partial_verdicts field is a list of partial verdicts which complies to:
           - each one of those elements of the list correspond to one CHECK or VERIFY steps of the test description
            - first value of the list MUST be a "pass", "fail", "inconclusive" or eventually "error" partial verdict (
            string)
            - the second value MUST be a string with a description of partial verdict (intended for the user)
            - more values elements MAY be added to the list

    """

    _msg_data_template = {
        "_type": "analysis.interop.testcase.analyze.reply",
        "ok": True,
        "verdict": "pass",
        "analysis_type": "postmortem",
        "description": "The test purpose has been verified without any fault detected",
        "review_frames": [],
        "token": "0lzzb_Bx30u8Gu-xkt1DFE1GmB4",
        "partial_verdicts": [
            [
                "pass",
                "<Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON 43521] GET /test> Match: CoAP(type=0, code=1)"
            ],

            [
                "pass",
                "<Frame   2: [127.0.0.1 -> 127.0.0.1] CoAP [ACK 43521] 2.05 Content > Match: CoAP(code=69, "
                "mid=0xaa01, \
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

    # # # # # # DISSECTION MESSAGES # # # # # #


class MsgDissectionDissectCapture(Message):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Request (service)

    Pub/Sub: coordination -> dissection, analysis -> dissection

    Description: TBD
    """

    PCAP_COAP_GET_OVER_TUN_INTERFACE_base64 = \
        "1MOyoQIABAAAAAAAAAAAAMgAAABlAAAAqgl9WK8aBgA7AAAAOwAAAGADPxUAExFAu7s" \
        "AAAAAAAAAAAAAAAAAAbu7AAAAAAAAAAAAAAAAAALXvBYzABNZUEABcGO0dGVzdMECqg" \
        "l9WMcaBgCQAAAAkAAAAGAAAAAAaDr//oAAAAAAAAAAAAAAAAAAA7u7AAAAAAAAAAAAA" \
        "AAAAAGJAAcTAAAAALu7AAAAAAAAAAAAAAAAAAK7uwAAAAAAAAAAAAAAAAACBAgAAAAA" \
        "AABgAz8VABMRQLu7AAAAAAAAAAAAAAAAAAG7uwAAAAAAAAAAAAAAAAAC17wWMwATWVB" \
        "AAXBjtHRlc6oJfVjSGgYAOwAAADsAAABgAz8VABMRP7u7AAAAAAAAAAAAAAAAAAG7uw" \
        "AAAAAAAAAAAAAAAAAC17wWMwATWVBAAXBjtHRlc3TBAg=="

    routing_key = "control.dissection.service"

    _msg_data_template = {
        "_type": "dissection.dissectcapture",
        "file_enc": "pcap_base64",
        "filename": "TD_COAP_CORE_01.pcap",
        "value": PCAP_COAP_GET_OVER_TUN_INTERFACE_base64,
        "protocol_selection": "coap",
    }


class MsgDissectionDissectCaptureReply(MsgReply):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Reply (service)

    Pub/Sub: Dissector -> Coordinator, Dissector -> Analyzer

    Description: TBD
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
        "_type": "dissection.dissectcapture.reply",
        "ok": True,
        "token": "0lzzb_Bx30u8Gu-xkt1DFE1GmB4",
        "frames": _frames_example
    }


class MsgDissectionAutoDissect(Message):
    """
    Requirements: Testing Tool MUST publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description: Used to indicate to the GUI the dissection of the exchanged packets.
        - GUI MUST display this info during execution:
            - interop session
            - conformance session
            - performance ?
            - privacy?

    """
    routing_key = "control.dissection"

    _frames_example = MsgDissectionDissectCaptureReply._frames_example

    _msg_data_template = {
        "_type": "dissection.autotriggered",
        "token": "0lzzb_Bx30u8Gu-xkt1DFE1GmB4",
        "frames": _frames_example,
        "testcase_id": "TBD",
        "testcase_ref": "TBD"
    }

    # # # # # # PRIVACY TESTING TOOL MESSAGES # # # # # #


class MsgPrivacyAnalyze(Message):
    """
        Testing Tool's MUST-implement.
        Analyze PCAP File for Privacy checks.
    """
    routing_key = "control.privacy.service"

    # TODO: This message should be update with a valuable privacy example
    # PCAP_COAP_GET_OVER_TUN_INTERFACE_base64 =
    # "1MOyoQIABAAAAAAAAAAAAMgAAABlAAAAqgl9WK8aBgA7AAAAOwAAAGADPxUAExFAu7s" \
    #
    # "AAAAAAAAAAAAAAAAAAbu7AAAAAAAAAAAAAAAAAALXvBYzABNZUEABcGO0dGVzdMECqg" \
    #
    # "l9WMcaBgCQAAAAkAAAAGAAAAAAaDr//oAAAAAAAAAAAAAAAAAAA7u7AAAAAAAAAAAAA" \
    #
    # "AAAAAGJAAcTAAAAALu7AAAAAAAAAAAAAAAAAAK7uwAAAAAAAAAAAAAAAAACBAgAAAAA" \
    #
    # "AABgAz8VABMRQLu7AAAAAAAAAAAAAAAAAAG7uwAAAAAAAAAAAAAAAAAC17wWMwATWVB" \
    #
    # "AAXBjtHRlc6oJfVjSGgYAOwAAADsAAABgAz8VABMRP7u7AAAAAAAAAAAAAAAAAAG7uw" \
    #                                           "AAAAAAAAAAAAAAAAAC17wWMwATWVBAAXBjtHRlc3TBAg=="

    PCAP_COAP_GET_OVER_TUN_INTERFACE_base64 = \
        "Cg0NCpgAAABNPCsaAQAAAP//////////AwAuAE1hYyBPUyBYIDEwLjEyLjQsIGJ1aWxk" \
        "IDE2RTE5NSAoRGFyd2luIDE2LjUuMCkAAAQAPQBEdW1wY2FwIChXaXJlc2hhcmspIDIu" \
        "Mi4wICh2Mi4yLjAtMC1nNTM2OGM1MCBmcm9tIG1hc3Rlci0yLjIpAAAAAAAAAJgAAAAB" \
        "AAAAXAAAAAAAAAAAAAQAAgAEAHR1bjAJAAEABgAAAAwALgBNYWMgT1MgWCAxMC4xMi40" \
        "LCBidWlsZCAxNkUxOTUgKERhcndpbiAxNi41LjApAAAAAAAAXAAAAAUAAABsAAAAAAAA" \
        "AIdOBQCsif6eAQAcAENvdW50ZXJzIHByb3ZpZGVkIGJ5IGR1bXBjYXACAAgAh04FAN2Z" \
        "ip4DAAgAh04FAKGJ/p4EAAgAAAAAAAAAAAAFAAgAAAAAAAAAAAAAAAAAbAAAAA=="

    _msg_data_template = {
        "_type": "privacy.analyze",
        "value": PCAP_COAP_GET_OVER_TUN_INTERFACE_base64,
        "file_enc": "pcap_base64",
        "filename": "TD_PRIVACY_DEMO_01.pcap",
    }


class MsgPrivacyAnalyzeReply(MsgReply):
    """
            Testing Tool's MUST-implement.
            Response of Analyze request from GUI
    """

    _privacy_empty_report = {"type": "Anomalies Report",
                             "protocols": ["coap"],
                             "conversation": [],
                             "status": "none",
                             "testing_tool": "Privacy Testing Tool",
                             "byte_exchanged": 0,
                             "timestamp": 1493798811.53124,
                             "is_final": True,
                             "packets": {},
                             "version": "0.0.1"}

    _msg_data_template = {
        "_type": "privacy.analyze.reply",
        "ok": True,
        "verdict": _privacy_empty_report,
        "testcase_id": "TBD",
    }


class MsgPrivacyGetConfiguration(Message):
    """
           Read Privacy configuration.
           GUI MUST display this info during setup
    """
    routing_key = "control.privacy.service"

    _msg_data_template = {
        "_type": "privacy.configuration.get",
    }


class MsgPrivacyGetConfigurationReply(MsgReply):
    """
           Read Privacy configuration.
           GUI MUST display this info during setup
    """
    routing_key = "control.privacy.service.reply"

    _msg_data_template = {
        "_type": "privacy.configuration.get.reply",
        "configuration": {},
        "ok": True,
    }


class MsgPrivacySetConfiguration(Message):
    """
        Write Privacy configuration.
        GUI MUST display this info during setup
    """
    routing_key = "control.privacy.service"

    CFG_EXAMPLE = dict()

    _msg_data_template = {
        "_type": "privacy.configuration.set",
        "configuration": CFG_EXAMPLE,
    }


class MsgPrivacySetConfigurationReply(MsgReply):
    """
        Write Privacy configuration.
        GUI MUST display this info during setup
    """
    routing_key = "control.privacy.service.reply"

    _msg_data_template = {
        "_type": "privacy.configuration.set.reply",
        "ok": True,
    }


class MsgPrivacyGetStatus(Message):
    """
    Testing Tool's MUST-implement.
    GUI -> Testing Tool
    GUI MUST display this info during execution:
     - privacy?

    """
    routing_key = "control.privacy.service"

    _msg_data_template = {
        "_type": "privacy.getstatus",
    }


class MsgPrivacyGetStatusReply(MsgReply):
    """
    Testing Tool's MUST-implement.
    GUI -> Testing Tool
    GUI MUST display this info during execution:
     - privacy?

    """

    REPORT_EXAMPLE = dict()
    routing_key = "control.privacy.service.reply"

    _msg_data_template = {
        "_type": "privacy.getstatus.reply",
        "verdict": REPORT_EXAMPLE,
        "status": "TBD",
        "ok": True,

    }


class MsgPrivacyIssue(Message):
    """
        Testing Tool's MUST-implement.
        Testing tools -> GUI
        GUI MUST display this info during execution:
         - privacy

        """
    routing_key = "control.privacy"

    _msg_data_template = {
        "_type": "privacy.issue",
        "verdict": json.dumps(MsgPrivacyAnalyzeReply._privacy_empty_report),
    }


# # # # # #   PERFORMANCE TESTING TOOL MESSAGES   # # # # # #

class MsgPerformanceHeartbeat(Message):
    """
    Requirements:   Timeline Controller MUST listen to event
                    Performance submodules MUST emit event periodically
    Type:           Event
    Typical_use:    Performance Submodules -> Timeline Controller
    Description:    The Timeline Controller verifies that all submodules are
                    active and in the correct state
    """
    routing_key = "control.performance"

    _msg_data_template = {
        "_type": "performance.heartbeat",
        "mod_name": "unknown",
        "status": "ready",  # ready, configured or failed
    }


class MsgPerformanceConfiguration(Message):
    """
    Requirements:   Timeline Controller MUST listen to event
    Type:           Event
    Typical_use:    Orchestrator -> Timeline Controller
    Description:    Carries the performance test configuration to the
                    Timeline Controller
    """
    routing_key = "control.performance"

    _msg_data_template = {
        "_type": "performance.configuration",
        "configuration": {  # As produced by configuration GUI
            "static": {},  # Static configuration of submodules
            "initial": {},  # Initial values for dynamic parameters
            "segments": [],  # Timeline segments
        }
    }


class MsgPerformanceSetValues(Message):
    """
    Requirements:   Performance Submodules MUST listen to event
    Type:           Event
    Typical_use:    Timeline Controller -> Performance Submodules
    Description:    During the test execution, the Timeline Controller will
                    periodically emit this event to the performance submodules
                    to update dynamic parameters
    """
    routing_key = "control.performance"

    _msg_data_template = {
        "_type": "performance.setvalues",
        "values": {}
    }


class MsgPerformanceStats(Message):
    """
    Requirements:   Performance Submodules SHOULD emit this event periodically
                    Visualization module SHOULD listen to this event
    Type:           Event
    Typical_use:    Performance Submodules -> Visualization
    Description:    During the test execution, the Performance Submodules
                    will periodically emit this event carrying current
                    performance statistics/measurements
    """
    routing_key = "control.performance"

    _msg_data_template = {
        "_type": "performance.stats",
        "mod_name": "unknown",
        "timestamp": 0,
        "stats": {},
    }


message_types_dict = {
    "log": MsgSessionLog,  # Any -> Any
    "chat": MsgSessionChat,  # GUI_x -> GUI_y
    "agent.configured": MsgAgentConfigured,  # TestingTool -> GUI
    "tun.start": MsgAgentTunStart,  # TestingTool -> Agent
    "tun.started": MsgAgentTunStarted,  # Agent -> TestingTool
    "serial.started": MsgAgentSerialStarted,  # Agent -> TestingTool
    "packet.sniffed.raw": MsgPacketSniffedRaw,  # Agent -> TestingTool
    "packet.to_inject.raw": MsgPacketInjectRaw,  # TestingTool -> Agent
    "session.interop.configuration": MsgInteropSessionConfiguration,  # Orchestrator -> TestingTool
    "testingtool.configured": MsgTestingToolConfigured,  # TestingTool -> Orchestrator, GUI
    "testingtool.component.ready": MsgTestingToolComponentReady,  # Testing Tool internal
    "testingtool.component.shutdown": MsgTestingToolComponentShutdown,  # Testing Tool internal
    "testingtool.ready": MsgTestingToolReady,  # GUI Testing Tool -> GUI
    "testingtool.terminate": MsgTestingToolTerminate,  # orchestrator -> TestingTool
    "testcoordination.testsuite.start": MsgTestSuiteStart,  # GUI -> TestingTool
    "testcoordination.testsuite.finish": MsgTestSuiteFinish,  # GUI -> TestingTool
    "testcoordination.testcase.ready": MsgTestCaseReady,  # TestingTool -> GUI
    "testcoordination.testcase.start": MsgTestCaseStart,  # GUI -> TestingTool
    "testcoordination.testcase.started": MsgTestCaseStarted,  # TestingTool -> GUI
    "testcoordination.step.stimuli.execute": MsgStepStimuliExecute,  # TestingTool -> GUI
    "testcoordination.step.stimuli.executed": MsgStepStimuliExecuted,  # GUI -> TestingTool
    "testcoordination.step.check.execute": MsgStepCheckExecute,  # TestingTool -> GUI
    "testcoordination.step.check.executed": MsgStepCheckExecuted,  # GUI -> TestingTool
    "testcoordination.step.verify.execute": MsgStepVerifyExecute,  # Testing Tool Internal
    "testcoordination.step.verify.executed": MsgStepVerifyExecuted,  # Testing Tool Internal
    "testcoordination.testcase.configuration": MsgTestCaseConfiguration,  # TestingTool -> GUI
    "testcoordination.configuration.execute": MsgConfigurationExecute,  # TestingTool -> GUI (or auto-iut)
    "testcoordination.configuration.executed": MsgConfigurationExecuted,  # GUI (or auto-iut) -> TestingTool
    "testcoordination.testcase.stop": MsgTestCaseStop,  # GUI -> TestingTool
    "testcoordination.testcase.restart": MsgTestCaseRestart,  # GUI -> TestingTool
    "testcoordination.testcase.skip": MsgTestCaseSkip,  # GUI -> TestingTool
    "testcoordination.testcase.select": MsgTestCaseSelect,  # GUI -> TestingTool
    # "testcoordination.testcase.finish": MsgTestCaseFinish,  # GUI -> TestingTool
    "testcoordination.testcase.finished": MsgTestCaseFinished,  # TestingTool -> GUI
    "testcoordination.testcase.verdict": MsgTestCaseVerdict,  # TestingTool -> GUI
    "testcoordination.testsuite.abort": MsgTestSuiteAbort,  # GUI -> TestingTool
    "testcoordination.testsuite.getstatus": MsgTestSuiteGetStatus,  # GUI -> TestingTool
    "testcoordination.testsuite.getstatus.reply": MsgTestSuiteGetStatusReply,  # TestingTool -> GUI (reply)
    "testcoordination.testsuite.gettestcases": MsgTestSuiteGetTestCases,  # GUI -> TestingTool
    "testcoordination.testsuite.gettestcases.reply": MsgTestSuiteGetTestCasesReply,  # TestingTool -> GUI (reply)
    "testcoordination.testsuite.report": MsgTestSuiteReport,  # TestingTool -> GUI
    "sniffing.start": MsgSniffingStart,  # Testing Tool Internal
    "sniffing.stop": MsgSniffingStop,  # Testing Tool Internal
    "sniffing.getcapture": MsgSniffingGetCapture,  # Testing Tool Internal
    "sniffing.getlastcapture": MsgSniffingGetCaptureLast,  # Testing Tool Internal
    "analysis.interop.testcase.analyze": MsgInteropTestCaseAnalyze,  # Testing Tool Internal
    "analysis.interop.testcase.analyze.reply": MsgInteropTestCaseAnalyzeReply,  # Testing Tool Internal
    "dissection.dissectcapture": MsgDissectionDissectCapture,  # Testing Tool Internal
    "dissection.dissectcapture.reply": MsgDissectionDissectCaptureReply,  # Testing Tool Internal
    "dissection.autotriggered": MsgDissectionAutoDissect,  # TestingTool -> GUI
    # GUI (or Orchestrator?) -> TestingTool
    # PRIVACY TESTING TOOL -> Reference: Luca Lamorte (UL)
    "privacy.analyze": MsgPrivacyAnalyze,  # TestingTool internal
    "privacy.analyze.reply": MsgPrivacyAnalyzeReply,  # TestingTool internal (reply)
    "privacy.getstatus": MsgPrivacyGetStatus,  # GUI -> TestingTool
    "privacy.getstatus.reply": MsgPrivacyGetStatusReply,  # GUI -> TestingTool (reply)
    "privacy.issue": MsgPrivacyIssue,  # TestingTool -> GUI,
    "privacy.configuration.get": MsgPrivacyGetConfiguration,  # TestingTool -> GUI,
    "privacy.configuration.get.reply": MsgPrivacyGetConfigurationReply,  # TestingTool -> GUI (reply),
    "privacy.configuration.set": MsgPrivacySetConfiguration,  # GUI -> TestingTool,
    "privacy.configuration.set.reply": MsgPrivacySetConfigurationReply,  # GUI -> TestingTool (reply),
    # PERFORMANCE TESTING TOOL -> Reference: Eduard Bröse (EANTC)
    "performance.heartbeat": MsgPerformanceHeartbeat,  # Perf. Submodules -> Timeline Controller
    "performance.configuration": MsgPerformanceConfiguration,  # Orchestrator -> Timeline Controller
    "performance.stats": MsgPerformanceStats,  # Perf. Submodules -> Visualization
    "performance.setvalues": MsgPerformanceSetValues,  # Timeline Controller -> Perf. Submodules

}

if __name__ == '__main__':
    # m1=MsgTestCaseStart()
    # print(json.dumps(m1.to_dict()))
    # print(m1.routing_key)
    # print(m1.to_json())
    # print(m1)

    m1 = MsgTestCaseStart(hola='verano')
    m2 = MsgTestCaseStart()
    # m2 = MsgTestCaseStart(routing_key = "lolo', hola='verano')

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
        "_type": "dissection.dissectcapture",
        "file_enc": "pcap_base64",
        "filename": "TD_COAP_CORE_01.pcap",
        "protocol_selection": "coap",
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
