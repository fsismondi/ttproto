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
- if event is a service request then the routing key (r_key) is someRpcExecutionEvent.request
- a reply to a service will be on topic/r_key : someRpcExecutionEvent.reply
- reply.correlation_id = request.correlation_id


Usage:
------
>>> m = MsgTestCaseSkip(testcase_id = 'some_testcase_id')
>>> m
MsgTestCaseSkip(_api_version = 1.0.3, description = Skip testcase, node = someNode, testcase_id = some_testcase_id, )
>>> m.routing_key
'testsuite.testcase.skip'
>>> m.message_id # doctest: +SKIP
'802012eb-24e3-45c4-9dcc-dc293c584f63'
>>> m.testcase_id
'some_testcase_id'

# also we can modify some of the fields (rewrite the default ones)
>>> m = MsgTestCaseSkip(testcase_id = 'TD_COAP_CORE_03')
>>> m
MsgTestCaseSkip(_api_version = 1.0.3, description = Skip testcase, node = someNode, testcase_id = TD_COAP_CORE_03, )
>>> m.testcase_id
'TD_COAP_CORE_03'

# and even export the message in json format (for example for sending the message though the amqp event bus)
>>> m.to_json()
'{"_api_version": "1.0.3", "description": "Skip testcase", "node": "someNode", "testcase_id": "TD_COAP_CORE_03"}'

# We can use the Message class to import json into Message objects:
>>> m=MsgTestSuiteStart()
>>> m.routing_key
'testsuite.start'
>>> m.to_json()
'{"_api_version": "1.0.3", "description": "Test suite START command"}'
>>> json_message = m.to_json()
>>> obj=Message.load(json_message,'testsuite.start', None )
>>> obj
MsgTestSuiteStart(_api_version = 1.0.3, description = Test suite START command, )
>>> type(obj) # doctest: +SKIP
<class '__main__.MsgTestSuiteStart'>

# We can use the library for generating error responses:
# the request:
>>> m = MsgSniffingStart()
>>>

# the error reply (note that we pass the message of the request to build the reply):
>>> err = MsgErrorReply(m)
>>> err
MsgErrorReply(_api_version = 1.0.3, error_code = Some error code TBD, error_message = Some error message TBD, ok = False, )

# properties of the message are auto-generated:
>>> m.reply_to
'sniffing.start.reply'
>>> err.routing_key
'sniffing.start.reply'
>>> m.correlation_id # doctest: +SKIP
'360b0f67-4455-43e3-a00f-eca91f2e84da'
>>> err.correlation_id # doctest: +SKIP
'360b0f67-4455-43e3-a00f-eca91f2e84da'

# we can get all the AMQP properties also as a dict:
>>> err.get_properties() # doctest: +SKIP
'{'timestamp': 1515172549, 'correlation_id': '16257581-06be-4088-a1f6-5672cc73d8f2', 'message_id': '1ec12c2b-33c7-44ad-97b8-5099c4d52e81', 'content_type': 'application/json'}'


"""

from collections import OrderedDict
import time
import json
import uuid

API_VERSION = '1.0.3'


class NonCompliantMessageFormatError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Message(object):
    def __init__(self, **kwargs):
        global API_VERSION

        try:
            # hard copy the message template
            self._msg_data = {k: v for k, v in self._msg_data_template.items()}
        except AttributeError:  # if message is built directly using Message class then there's no data template
            self._msg_data = {}
            self._msg_data_template = {}

        # init properties
        self._properties = dict(
            content_type="application/json",
            message_id=str(uuid.uuid4()),
            timestamp=int(time.time())
        )

        try:
            if self.routing_key.endswith(".request"):
                self._properties["reply_to"] = self.routing_key.replace(".request", ".reply")
                self._properties["correlation_id"] = self._properties["message_id"]
        except AttributeError:
            pass

        # rewrite default data fields with the passed args
        self._msg_data.update(kwargs)

        # add API's version
        if "_api_version" not in self._msg_data:
            self._msg_data["_api_version"] = API_VERSION

        # add values as object's attributes
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

        return resp

    def to_odict(self):
        resp = {}
        # let's use sorted so API returns items inside always in the same order
        for field in sorted(self._msg_data.keys()):
            resp[field] = getattr(self, field)

        return OrderedDict(sorted(resp.items(), key=lambda t: t[0]))  # sorted by key

    def to_json(self):
        return json.dumps(self.to_odict())

    def get_properties(self):
        resp = dict()
        for field in self._properties:
            resp[field] = getattr(self, field)
        return resp

    def __str__(self):
        s = " - " * 20 + "\n"
        s += "Message routing key: %s" % self.routing_key
        s += "\n -  -  - \n"
        s += "Message properties: %s" % json.dumps(self.get_properties(), indent=4, )
        s += "\n -  -  - \n"
        s += "Message body: %s" % json.dumps(self.to_odict(), indent=4, )
        s += "\n" + " - " * 20
        return s

    def update_properties(self, **kwargs):
        for key, value in kwargs.items():
            # if key in self._properties:
            #     setattr(self, key, value)
            setattr(self, key, value)

    @classmethod
    def load(cls, json_body, routing_key, properties=None):
        """
        Builds a python object representation of the AMQP message based on the ones defined by the event bus API.

        :param json_body: json description of message's body (amqp payload)
        :param routing_key: Maps to the right Message builder, passed argument cannot contain special char like * or #
        :param properties: Used for building more complete complex representation (e.g. for reply_to corre_id params)
        :return: The python Message object or subclass (e.g. MsgPacketSniffedRaw)

        about r_key matching mechanism:
            fromAgent.coap_client.packet.raw -> matches fromAgent.*.packet.raw -> returns MsgPacketSniffedRaw

        # We can use the Message class to build Message objects from json + rkey:
        >>> m=MsgSniffingGetCapture()
        >>> m.routing_key
        'sniffing.getcapture.request'
        >>> m.to_json()
        '{"_api_version": "1.0.3", "capture_id": "TD_COAP_CORE_01"}'
        >>> json_message = m.to_json()
        >>> json_message
        '{"_api_version": "1.0.3", "capture_id": "TD_COAP_CORE_01"}'
        >>> obj=Message.load(json_message,'testsuite.start', None )
        >>> type(obj) # doctest
        <class '__main__.MsgTestSuiteStart'>


        """
        global rk_pattern_to_message_type_map

        props_dict = {}

        # get message type from predefined rkey patterns
        message_type = rk_pattern_to_message_type_map.get_message_type(routing_key)

        # build message skeleton (all fields as None)
        default_values_dict = message_type().to_dict()
        payload_dict = dict.fromkeys(default_values_dict.keys(), None)

        # fill messages from provided json
        payload_dict.update(json.loads(json_body))
        built_message = message_type(**payload_dict)

        # let's process the properties arguments
        if properties is None:
            pass
        elif type(properties) is dict:
            props_dict.update(properties)
        else:
            raise NotImplementedError('Incompatible properties input or not yet supported')

        # let's update the messages properties
        if properties:
            built_message.update_properties(**props_dict)

        return built_message

    @classmethod
    def load_from_pika(cls, method, props, body):
        """
        Builds a python object representation of the AMQP message based on the ones defined by the event bus API.
        Takes as arguments pika objects method, properties and body returned by channel.basic_consume method
        """
        global rk_pattern_to_message_type_map

        props_dict = {
            'content_type': props.content_type,
            'delivery_mode': props.delivery_mode,
            'correlation_id': props.correlation_id,
            'reply_to': props.reply_to,
            'message_id': props.message_id,
            'timestamp': props.timestamp,
            'user_id': props.user_id,
            'app_id': props.app_id,
        }

        routing_key = method.routing_key
        json_body = body.decode('utf-8')

        return Message.load(json_body, routing_key, props_dict)

    @classmethod
    def from_json(cls, body):
        """
        :param body: json string or string encoded as utf-8
        :return:  Message object generated from the body
        :raises NonCompliantMessageFormatError: If the message cannot be build from the provided json
        """

        raise DeprecationWarning()

        # if type(body) is str:
        #     message_dict = json.loads(body)
        # # Note: pika re-encodes json.dumps strings as utf-8 for some reason, the following line undoes this
        # elif type(body) is bytes:
        #     message_dict = json.loads(body.decode("utf-8"))
        # else:
        #     raise NonCompliantMessageFormatError("Not a Json")
        #
        # return cls.from_dict(message_dict)

    @classmethod
    def from_dict(cls, message_dict):
        """
        :param body: dict
        :return:  Message object generated from the body
        :raises NonCompliantMessageFormatError: If the message cannot be build from the provided json
        """

        raise DeprecationWarning()

        # assert type(message_dict) is dict
        #
        # message_type = message_dict["_type"]
        #
        # if message_type in message_types_dict:
        #     return message_types_dict[message_type](**message_dict)
        # else:
        #     raise NonCompliantMessageFormatError("Cannot load json message: %s" % str(message_dict))

    def __repr__(self):
        ret = "%s(" % self.__class__.__name__
        for key, value in self.to_odict().items():
            ret += "%s = %s, " % (key, value)
        ret += ")"
        return ret


class RoutingKeyToMessageMap:
    """
    Special dict to map routing keys to messages of Message type.
    Lookup is slow but it's due to the fact of using WILDCARDs (no hash mechanism can be used :/ )

    example of use:
        >>> from messages import *
        >>> r_map=RoutingKeyToMessageMap({'fromAgent.*.packet.raw':MsgPacketSniffedRaw })
        >>> r_map
        {'fromAgent.*.packet.raw': <class 'messages.MsgPacketSniffedRaw'>}
        >>> r_map.get_message_type('fromAgent.agent1.packet.raw')
        <class 'messages.MsgPacketSniffedRaw'>
        >>> r_map.get_message_type('blabla.agent1.packet.raw')
        Traceback (most recent call last):
          File "<stdin>", line 1, in <module>
          File "/Users/fsismondi/dev/f-interop-utils/messages.py", line 258, in get_message_type
            raise KeyError("%s not found" % routing_key)
        KeyError: 'blabla.agent1.packet.raw not found'
        >>>

    """
    # TODO implement # wildcard
    WILDCARDS = ('*', '#')
    TERM_SEPARATOR = '.'

    def __init__(self, rkey_to_message_dict):
        self.rkey_to_message_dict = rkey_to_message_dict

    def __repr__(self):
        return repr(self.rkey_to_message_dict)

    def get_message_type(self, routing_key):
        for key in self.rkey_to_message_dict.keys():
            if self.equals(key, routing_key):
                return self.rkey_to_message_dict[key]
        raise KeyError("%s not found in mapping rkey patterns -> messages table" % routing_key)

    @classmethod
    def equals(cls, r1, r2):

        def equal_terms(term_1, term_2):
            if term_1 == '*' or term_2 == '*':
                return True
            else:
                return term_1 == term_2

        complex_matching = False

        for wc in cls.WILDCARDS:
            if wc in r1 or wc in r2:
                complex_matching = True
                break

        if '#' in r1 or '#' in r2:
            raise NotImplementedError("Wildcard # still not supported in matching mechanism")

        if not complex_matching:
            return r1 == r2
        else:
            if len(r1.split(cls.TERM_SEPARATOR)) != len(r2.split(cls.TERM_SEPARATOR)):
                return False
            else:
                for term1, term2 in zip(r1.split(cls.TERM_SEPARATOR), r2.split(cls.TERM_SEPARATOR)):
                    if not equal_terms(term1, term2):
                        return False
                    else:
                        continue
                return True


class MsgReply(Message):
    """
    Auxiliary class which creates replies messages with fields based on the request.
    Routing key, corr_id are generated based on the request message
    """

    def __init__(self, request_message=None, **kwargs):

        if request_message and hasattr(request_message, "routing_key"):
            if request_message.routing_key.endswith(".request"):
                self.routing_key = request_message.routing_key.replace(".request", ".reply")

            # if not data template, then let's build one for a reply
            # (possible when creating a MsgReply directly and not by using subclass)
            if not hasattr(self, "_msg_data_template"):
                self._msg_data_template = {
                    "ok": True,
                }

            super(MsgReply, self).__init__(**kwargs)

            # overwrite correlation id template and attribute
            self._properties["correlation_id"] = request_message.correlation_id
            self.correlation_id = request_message.correlation_id

        else:  # note this doesnt generate amqp properties
            import logging
            logging.warning('(!) messages library | lazy response built, generating reply message without corr_id')
            super(MsgReply, self).__init__(**kwargs)

    def correlate_to(self, request_message):
        """
        add to reply message the right correlation information to request
        """
        # overwrite correlation id template and attribute
        self._properties["correlation_id"] = request_message.correlation_id
        self.correlation_id = request_message.correlation_id


class MsgErrorReply(MsgReply):
    """
    see section "F-Interop conventions" on top
    """

    def __init__(self, request_message, **kwargs):
        assert request_message
        super(MsgErrorReply, self).__init__(request_message, **kwargs)

    _msg_data_template = {
        "ok": False,
        "error_message": None,
        "error_code": None
    }


# # # # # # CORE API messages # # # # #

class MsgOrchestratorVersionReq(Message):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: UI -> SO

    Description: Message for returning current version of SO
    """
    routing_key = "orchestrator.version.request"

    _msg_data_template = {
    }


class MsgOrchestratorUsersList(Message):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: UI -> SO

    Description: Message for returning user list of SO
    """
    routing_key = "orchestrator.users.list.request"

    _msg_data_template = {
    }


class MsgOrchestratorUserAdd(Message):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: UI -> SO

    Description: Message for adding a user to SO
    """

    routing_key = "orchestrator.users.add.request"

    _msg_data_template = {
    }


class MsgOrchestratorUserDelete(Message):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: UI -> SO

    Description: Message for deleting a user from SO
    """

    routing_key = "orchestrator.users.delete.request"

    _msg_data_template = {
    }


class MsgOrchestratorUserGet(Message):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: UI -> SO

    Description: Message for getting a user from SO
    """

    routing_key = "orchestrator.users.get.request"

    _msg_data_template = {
    }


class MsgOrchestratorSessionsList(Message):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: UI -> SO

    Description: Message for listing sessions from SO
    """
    routing_key = "orchestrator.sessions.list.request"

    _msg_data_template = {
    }


class MsgOrchestratorSessionsGet(Message):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: UI -> SO

    Description: Message for getting a session from SO
    """
    routing_key = "orchestrator.sessions.get.request"

    _msg_data_template = {
    }


class MsgOrchestratorSessionsAdd(Message):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: UI -> SO

    Description: Message for adding a session to SO
    """
    routing_key = "orchestrator.sessions.add.request"

    _msg_data_template = {
    }


class MsgOrchestratorSessionsDelete(Message):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: UI -> SO

    Description: Message for deleting a session to SO
    """

    routing_key = "orchestrator.sessions.delete.request"

    _msg_data_template = {
    }


class MsgOrchestratorSessionsUpdate(Message):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: UI -> SO

    Description: Message for updating a session from SO
    """

    routing_key = "orchestrator.sessions.update.request"
    _msg_data_template = {
    }


class MsgOrchestratorTestsGet(Message):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: UI -> SO

    Description: Message for getting tests from SO
    """
    routing_key = "orchestrator.tests.get.request"

    _msg_data_template = {
    }


class MsgOrchestratorTestsGetContributorName(Message):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: UI -> SO

    Description: Message for getting tests from SO with contributor and name
    """
    routing_key = "orchestrator.tests.get_contributor_name.request"

    _msg_data_template = {
    }


# # # # # # GUI API messages # # # # # # # #

class MsgUiReply(Message):
    routing_key = "ui.user.all.reply"

    _msg_data_template = {
        "fields": [
        ]
    }


class MsgUiDisplay(Message):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: TT -> UI

    Description: Message to display in user interface
    """
    routing_key = "ui.user.all.display"

    _msg_data_template = {
        "level": None,
        "tags": {},
        "fields": [
            {
                "type": "p",
                "value": "Hello World!"
            },
        ]
    }


class MsgUiRequest(Message):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: TT -> UI

    Description: Message for requesting action or information to user
    """
    routing_key = "ui.user.all.request"

    _msg_data_template = {
        "tags": {},
        "fields": [
            {
                "name": "input_name",
                "type": "text"
            },
        ]
    }


class MsgUiRequestSessionConfiguration(Message):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: TT -> UI

    Description: Message for requesting session information to UI
    """
    routing_key = "ui.core.session.get.request"

    _msg_data_template = {
    }


class MsgUiRequestQuestionRadio(MsgUiRequest):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: TT -> UI

    Description: Message for radio request on UI
    """

    _msg_data_template = {
        "tags": {},
        "fields": [
            {
                "name": "True",
                "type": "radio",
                "value": True
            },
            {
                "name": "False",
                "type": "radio",
                "value": False
            },
        ]
    }


class MsgUiRequestQuestionCheckbox(MsgUiRequest):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: TT -> UI

    Description: Message for checkbox request on UI
    """

    _msg_data_template = {
        "tags": {},
        "fields": [
            {
                "name": "Choice1",
                "label": "Choice1",
                "type": "checkbox",
                "value": 0
            },
            {
                "name": "Choice2",
                "label": "Choice2",
                "type": "checkbox",
                "value": 1
            },
        ]
    }


class MsgUiRequestQuestionSelect(MsgUiRequest):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: TT -> UI

    Description: Message for select request on UI
    """

    _msg_data_template = {
        "tags": {},
        "fields": [
            {
                "name": "ideal_select",
                "type": "select",
                "options": [
                    {"label": "choice 1", "value": 1},
                    {"label": "choice 2", "value": 2},
                    {"label": "choice 3", "value": 3},
                ],
                "value": 1
            }
        ]
    }


class MsgUiRequestUploadFile(MsgUiRequest):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: TT -> UI

    Description: Message for file upload request on UI
    """

    _msg_data_template = {
        "tags": {},
        "fields": [
            {
                "name": "upload a file",
                "type": "file"
            }
        ]
    }


class MsgUiRequestTextInput(MsgUiRequest):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: TT -> UI

    Description: Message for requesting a text input on UI
    """

    _msg_data_template = {
        "tags": {},
        "fields": [
            {
                "name": "input_name",
                "type": "text"
            },
        ]
    }


class MsgUiRequestConfirmationButton(MsgUiRequest):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: TT -> UI

    Description: Message for requesting confirmation button
    """

    _msg_data_template = {
        "tags": {},
        "fields": [
            {
                "name": "test_button",
                "type": "button",
                "value": True
            },
        ]
    }


class MsgUiDisplayMarkdownText(MsgUiDisplay):
    """
    Requirements: ...

    Type: Event

    Pub/Sub: TT -> UI

    Description: Message for displaying Mardown text to user interface
    """

    _msg_data_template = {
        "level": None,
        "tags": {},
        "fields": [
            {
                "type": "p",
                "value": "Hello World!"
            },
        ]
    }


# # # # # # AGENT MESSAGES # # # # # #


class MsgAgentTunStart(Message):
    """
    Requirements: Testing Tool MAY implement (if IP tun needed)

    Type: Event

    Pub/Sub: Testing Tool -> Agent

    Description: Message for triggering start IP tun interface in OS where the agent is running
    """
    routing_key = "toAgent.someAgentName.ip.tun.start"

    _msg_data_template = {
        "name": "agent_TT",
        "ipv6_prefix": "bbbb",
        "ipv6_host": ":3",
        "ipv6_no_forwarding": False,
        "ipv4_host": None,
        "ipv4_network": None,
        "ipv4_netmask": None,
    }


class MsgAgentTunStarted(Message):
    """
    Description: Message for indicating that agent tun has been started

    Type: Event

    Pub/Sub: Agent -> Testing Tool

    Description: TBD
    """
    routing_key = "fromAgent.someAgentName.ip.tun.started"

    _msg_data_template = {
        "name": "agent_TT",
        "ipv6_prefix": "bbbb",
        "ipv6_host": ":3",
        "ipv4_host": None,
        "ipv4_network": None,
        "ipv4_netmask": None,
        "ipv6_no_forwarding": False,
    }


class MsgAgentSerialStarted(Message):
    """
    Description: Message for indicating that agent serial interface has been started

    Type: Event

    Pub/Sub: Testing Tool -> Agent

    Description: TBD
    """
    routing_key = "fromAgent.someAgentName.802154.serial.started"

    _msg_data_template = {
        "name": "tbd",
        "port": "tbd",
        "boudrate": "tbd",
    }


class MsgPacketInjectRaw(Message):
    """
    Description: Message to be captured by the agent an push into the correct embedded interface (e.g. tun, serial, etc..)

    Type: Event

    Pub/Sub: Testing Tool -> Agent

    Description: TBD
    """

    # (!) r.key depends on the agent_id and the agent interface being used, re-write after creation
    routing_key = "toAgent.someAgentName.ip.tun.packet.raw"

    _msg_data_template = {
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

    # (!) r.key depends on the agent_id and the agent interface being used, re-write after creation
    routing_key = "fromAgent.someAgentName.ip.tun.packet.raw"

    _msg_data_template = {
        "timestamp": "1488586183.45",
        "interface_name": "tun0",
        "data": [96, 0, 0, 0, 0, 36, 0, 1, 254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 255, 2, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 22, 58, 0, 5, 2, 0, 0, 1, 0, 143, 0, 112, 7, 0, 0, 0, 1, 4, 0, 0, 0, 255, 2, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]}


# # # # # # SESSION MESSAGES # # # # # #

class MsgTestingToolTerminate(Message):
    """
    Requirements: TT MUST listen to event, and handle a gracefully termination of all it's processes

    Type: Event

    Pub/Sub: GUI, (or Orchestrator) -> Testing Tool

    Description: Testing tool should stop all it's processes gracefully.
    """
    routing_key = "testingtool.terminate"

    _msg_data_template = {
        "description": "Command TERMINATE testing tool execution"
    }


class MsgTestingToolReady(Message):
    """
    Requirements: TT MUST publish event as soon as TT is up and listening on the event bus

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description: Used to indicate to the GUI that testing is ready to start the test suite
    """
    routing_key = "testingtool.ready"

    _msg_data_template = {
        "description": "Testing tool READY to start test suite."
    }


class MsgTestingToolComponentReady(Message):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Event

    Pub/Sub: Any Testing tool's component -> Test Coordinator

    Description: Once a testing tool's component is ready, it should publish a compoennt ready message
    """
    routing_key = "testingtool.component.ready"

    _msg_data_template = {
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
    routing_key = "chat"

    _msg_data_template = {
        "user_name": "Ringo",
        "node": "tbd",
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
        "component": "misc",
        "message": "I've got blisters on my fingers!"
    }


# TODO depricate this in favour of new UI call for getting the config
class MsgSessionConfiguration(Message):
    """
    Requirements: TT MUST listen to event, and configure accordingly

    Type: Event

    Pub/Sub: Orchestrator -> Testing Tool

    Description: TT MUST listen to this message and configure the testsuite correspondingly
    """
    routing_key = "session.configuration"

    _msg_data_template = {
        "session_id": "666",
        "configuration": {
            'testsuite.testcases': [
                'someTestCaseId1',
                'someTestCaseId2'
            ]
        },
        "testing_tools": "f-interop/someTestToolId",
        "users": [
            "u1",
            "f-interop"
        ],
    }


class MsgAgentConfigured(Message):
    """
    Requirements: Testing Tool SHOULD publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description: The goal is to notify GUI when agents are ready to start the session
    """

    routing_key = "fromAgent.someAgentName.configured"

    _msg_data_template = {
        "description": "Agent successfully CONFIGURED",
        'name': 'agent_TT'
    }


class MsgTestingToolConfigured(Message):
    """
    Requirements: TT MUST publish event once session.configuration message has been processed.

    Type: Event

    Pub/Sub: Testing Tool -> Orchestrator, GUI

    Description: The goal is to notify orchestrator and other components that the testing tool has been configured
    """

    routing_key = "testingtool.configured"

    _msg_data_template = {
        "description": "Testing tool CONFIGURED",
        "session_id": "TBD",
        "testing_tools": "f-interop/interoperability-coap",
    }


# TODO deprecate this message
class MsgSessionCreated(Message):
    """
    Requirements: Session Orchestrator MUST publish message on common-services channel (on every session creation)

    Type: Event

    Pub/Sub: SO -> viz tools

    Description: The goal is to notify viz tools about new sessions
    """

    routing_key = "orchestrator.session.created"

    _msg_data_template = {
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
    routing_key = "testingtool.component.shutdown"

    _msg_data_template = {
        "component": "SomeComponent",
        "description": "Component SHUTDOWN. Bye!"
    }

    # # # # # # TEST COORDINATION MESSAGES # # # # # #


class MsgTestSuiteStart(Message):
    """
    Requirements: TT MUST listen to event and start the test suite right after reception. MsgTestSuiteStarted

    Type: Event

    Pub/Sub: GUI -> Testing Tool

    Description: tbd
    """

    routing_key = "testsuite.start"

    _msg_data_template = {
        "description": "Test suite START command"
    }


class MsgTestSuiteStarted(Message):
    """
    Requirements: Testing Tool SHOULD publish to event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description: tbd
    """

    routing_key = "testsuite.started"

    _msg_data_template = {
        "description": "Test suite STARTED"
    }


class MsgTestSuiteFinish(Message):
    """
    Requirements: TT MUST listen to event

    Type: Event

    Pub/Sub: GUI -> Testing Tool

    Description: tbd
    """

    routing_key = "testsuite.finish"

    _msg_data_template = {
        "description": "Test suite FINISH command"
    }


class MsgTestCaseReady(Message):
    """
    Requirements: TT MUST publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description:
        - Used to indicate to the GUI (or automated-iut) which is the next test case to be executed.
        - This message is normally followed by a MsgTestCaseStart (from GUI-> Testing Tool)
    """

    routing_key = "testsuite.testcase.ready"

    _msg_data_template = {
        "description": "Next test case to be executed is TD_COAP_CORE_01",
        "testcase_id": "TD_COAP_CORE_01",
        "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_01",
        "objective": "Perform GET transaction(CON mode)",
        "state": None
    }


class MsgTestCaseStart(Message):
    """
    Requirements: TT MUST listen to event

    Type: Event

    Pub/Sub: GUI -> Testing Tool

    Description:
        - Message used for indicating the testing tool to start the test case (the one previously selected)
        - if testcase_id is Null then testing tool starts previously announced testcase in message
        "testcoordination.testcase.ready",
    """
    routing_key = "testsuite.testcase.start"

    _msg_data_template = {
        "description": "Test case START command",
        "testcase_id": None,
    }


class MsgTestCaseStarted(Message):
    """
    Requirements: Testing Tool SHOULD publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description:
        - Message used for indicating that testcase has started
    """
    routing_key = "testsuite.testcase.started"

    _msg_data_template = {
        "description": "Test case STARTED",
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

    routing_key = "testsuite.testcase.configuration"
    _msg_data_template = {
        "configuration_id": "COAP_CFG_01",
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

    routing_key = "testsuite.testcase.configuration.execute"

    _msg_data_template = {
        "configuration_id": "COAP_CFG_01",
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

    routing_key = "testsuite.testcase.configuration.executed"

    _msg_data_template = {
        "description": "IUT has been configured",
        "node": "coap_server",
        "ipv6_address": None  # format -> bbbb::2 (if not provided then uses default)
    }


class MsgTestCaseStop(Message):
    """
    Requirements: TT MUST listen to event

    Type: Event

    Pub/Sub: GUI & automated-iut -> Testing Tool

    Description:
        - Message used for indicating the testing tool to stop the test case (the one running).
    """

    routing_key = "testsuite.testcase.stop"

    _msg_data_template = {
        "description": "Event test case STOP"
    }


class MsgTestCaseRestart(Message):
    """
    Requirements: TT MUST listen to event

    Type: Event

    Pub/Sub: GUI -> Testing Tool

    Description: Restart the running test cases.
    """

    routing_key = "testsuite.testcase.restart"

    _msg_data_template = {
        "description": "Test case RESTART command"
    }


class MsgStepStimuliExecute(Message):
    """
    Requirements: TT MUST publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description:
        - Used to indicate to the GUI (or automated-iut) which is the stimuli step to be executed by the user (or
        automated-IUT).
    """

    routing_key = "testsuite.testcase.step.stimuli.execute"

    _msg_data_template = {
        "description": "Please execute TD_COAP_CORE_01_step_01",
        "step_id": "TD_COAP_CORE_01_step_01",
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
    Requirements: TT MUST listen to event

    Type: Event

    Pub/Sub: GUI (or automated-IUT)-> Testing Tool

    Description:
        - Used to indicate stimuli has been executed by user (and it's user-assisted iut) or by automated-iut
    """

    routing_key = "testsuite.testcase.step.stimuli.executed"

    _msg_data_template = {
        "description": "Step (stimuli) EXECUTED",
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

    routing_key = "testsuite.testcase.step.check.execute"

    _msg_data_template = {
        "description": "Please execute TD_COAP_CORE_01_step_02",
        "step_id": "TD_COAP_CORE_01_step_02",
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

    routing_key = "testsuite.testcase.step.check.executed"

    _msg_data_template = {
        "partial_verdict": "pass",
        "description": "TAT says: step complies (checks) with specification",
    }


class MsgStepVerifyExecute(Message):
    """
    Requirements: TT MUST publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI (or automated-IUT)

    Description:
        - Used to indicate to the GUI (or automated-iut) which is the verify step to be executed by the user (or
        automated-IUT).
    """

    routing_key = "testsuite.testcase.step.verify.execute"

    _msg_data_template = {
        "response_type": "bool",
        "description": "Please execute TD_COAP_CORE_01_step_04",
        "step_id": "TD_COAP_CORE_01_step_04",
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
    Requirements: TT MUST listen to event

    Type: Event

    Pub/Sub: GUI (or automated-IUT)-> Testing Tool

    Description:
        - Message generated by user (GUI or automated-IUT) declaring if the IUT VERIFY verifies the expected behaviour.
    """

    routing_key = "testsuite.testcase.step.verify.executed"

    _msg_data_template = {
        "description": "Step (verify) EXECUTED",
        "response_type": "bool",
        "verify_response": True,
        "node": "coap_client",
        "node_execution_mode": "user_assisted",
    }


class MsgTestCaseFinished(Message):
    """
    Requirements: TT MUST publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description:
        - Used for indicating to subscribers that the test cases has finished.
        - This message is followed by a verdict.
    """

    routing_key = "testsuite.testcase.finished"

    _msg_data_template = {
        "testcase_id": "TD_COAP_CORE_01",
        "testcase_ref": "TBD",
        "description": "Testcase finished"
    }


class MsgTestCaseSkip(Message):
    """
    Requirements: TT MUST listen to event

    Type: Event

    Pub/Sub: GUI (or automated-IUT)-> Testing Tool

    Description:
        - Used for skipping a test cases event when was previusly selected to be executed.
        - testcase_id (optional) : if not provided then current tc is skipped
        - node (mandatory): node requesting to skip test case
    """

    routing_key = "testsuite.testcase.skip"

    _msg_data_template = {
        "description": "Skip testcase",
        "testcase_id": None,
        "node": "someNode",
    }


class MsgTestCaseSelect(Message):
    """
    Requirements: TT MUST listen to event

    Type: Event

    Pub/Sub: GUI (or automated-IUT)-> Testing Tool

    Description: tbd

    """

    routing_key = "testsuite.testcase.select"

    _msg_data_template = {
        "testcase_id": "TD_COAP_CORE_03",
    }


class MsgTestSuiteAbort(Message):
    """
    Requirements: TT MUST listen to event

    Type: Event

    Pub/Sub: GUI (or automated-IUT)-> Testing Tool

    Description: Event test suite ABORT
    """

    routing_key = "testsuite.abort"

    _msg_data_template = {
        "description": "Test suite ABORT command"
    }


class MsgTestCaseAbort(Message):
    """
    Requirements: Testing Tool SHOULD listen to event

    Type: Event

    Pub/Sub: GUI (or automated-IUT)-> Testing Tool

    Description: Event for current test case ABORT
    """

    routing_key = "testsuite.testcase.abort"

    _msg_data_template = {
        "description": "Test case ABORT (current testcase) command"
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

    routing_key = "testsuite.status.request"

    _msg_data_template = {
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

    routing_key = "testsuite.status.reply"

    _msg_data_template = {
        "ok": True,
        "started": True,
        "testcase_id": "TD_COAP_CORE_01",
        "testcase_state": "executing",
        "step_id": "TD_COAP_CORE_01_step_01"

    }


class MsgTestSuiteGetTestCases(Message):
    """
    Requirements: Testing Tool SHOULD (MUST?) implement (other components should not subscribe to event)

    Type: Request (service)

    Pub/Sub: GUI -> Testing Tool

    Description: TBD
    """

    routing_key = "testsuite.testcases.list.request"

    _msg_data_template = {
    }


class MsgTestSuiteGetTestCasesReply(MsgReply):
    """
    Requirements: Testing Tool SHOULD (MUST?) implement (other components should not subscribe to event)

    Type: Reply (service)

    Pub/Sub: Testing Tool -> GUI

    Description: TBD
    """

    routing_key = "testsuite.testcases.list.reply"

    _msg_data_template = {
        "ok": True,
        "tc_list": [
            {
                "testcase_id": "TD_COAP_CORE_01",
                "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_01",
                "objective": "Perform GET transaction(CON mode)",
                "state": None
            },
            {
                "testcase_id": "TD_COAP_CORE_02",
                "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_02",
                "objective": "Perform DELETE transaction (CON mode)",
                "state": None
            },
            {
                "testcase_id": "TD_COAP_CORE_03",
                "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_03",
                "objective": "Perform PUT transaction (CON mode)",
                "state": None
            }
        ]
    }


class MsgTestCaseVerdict(Message):
    """
    Requirements: TT MUST publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description: Used to indicate to the GUI (or automated-iut) which is the final verdict of the testcase.
    """

    routing_key = "testsuite.testcase.verdict"

    _msg_data_template = {
        "verdict": "pass",
        "description": "No interoperability error was detected,",
        "partial_verdicts": [
            ["TD_COAP_CORE_01_step_02", None, "CHECK postponed", ""],
            ["TD_COAP_CORE_01_step_03", None, "CHECK postponed", ""],
            ["TD_COAP_CORE_01_step_04", "pass",
             "VERIFY step: User informed that the information was displayed correclty on his/her IUT", ""],
            ["CHECK_1_post_mortem_analysis", "pass",
             "<Frame   3: [bbbb::1 -> bbbb::2] CoAP [CON 43211] GET /test> Match: CoAP(type=0, code=1)"],
            ["CHECK_2_post_mortem_analysis", "pass",
             "<Frame   4: [bbbb::2 -> bbbb::1] CoAP [ACK 43211] 2.05 Content > Match: CoAP(code=69, "
             "mid=0xa8cb, tok=b'', pl=Not(b''))"],
            ["CHECK_3_post_mortem_analysis", "pass",
             "<Frame   4: [bbbb::2 -> bbbb::1] CoAP [ACK 43211] 2.05 Content > Match: CoAP(opt=Opt("
             "CoAPOptionContentFormat()))"]],
        "testcase_id": "TD_COAP_CORE_01",
        "testcase_ref": "http://f-interop.paris.inria.fr/tests/TD_COAP_CORE_01",
        "objective": "Perform GET transaction(CON mode)", "state": "finished"
    }


class MsgTestSuiteReport(Message):
    """
    Requirements: TT MUST publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description: Used to indicate to the GUI (or automated-iut) the final results of the test session.
    """

    routing_key = "testsuite.report"

    _msg_data_template = {
        "TD_COAP_CORE_01":
            {
                "verdict": "pass",
                "description": "No interoperability error was detected,",
                "partial_verdicts":
                    [
                        ["TD_COAP_CORE_01_step_02", None, "CHECK postponed", ""],
                        ["TD_COAP_CORE_01_step_03", None, "CHECK postponed", ""],
                        ["TD_COAP_CORE_01_step_04", "pass",
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

        "TD_COAP_CORE_02":
            {
                "verdict": "pass",
                "description": "No interoperability error was detected,",
                "partial_verdicts": [
                    ["TD_COAP_CORE_02_step_02", None, "CHECK postponed", ""],
                    ["TD_COAP_CORE_02_step_03", None, "CHECK postponed", ""],
                    ["TD_COAP_CORE_02_step_04", "pass",
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

    routing_key = "sniffing.start.request"

    _msg_data_template = {
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

    routing_key = "sniffing.start.reply"

    _msg_data_template = {
        "ok": True
    }


class MsgSniffingStop(Message):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Request (service)

    Pub/Sub: coordination -> sniffing

    Description: tbd
    """

    routing_key = "sniffing.stop.request"

    _msg_data_template = {
    }


class MsgSniffingStopReply(MsgReply):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Reply (service)

    Pub/Sub: sniffing -> coordination

    Description: tbd
    """

    routing_key = "sniffing.stop.reply"

    _msg_data_template = {
        "ok": True
    }


class MsgSniffingGetCapture(Message):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Request (service)

    Pub/Sub: coordination -> sniffing

    Description: tbd
    """

    routing_key = "sniffing.getcapture.request"

    _msg_data_template = {
        "capture_id": "TD_COAP_CORE_01",

    }


class MsgSniffingGetCaptureReply(MsgReply):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Reply (service)

    Pub/Sub: sniffing -> coordination

    Description: tbd
    """
    routing_key = "sniffing.getcapture.reply"

    _msg_data_template = {
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

    routing_key = "sniffing.getlastcapture.request"

    _msg_data_template = {
    }


class MsgSniffingGetCaptureLastReply(MsgReply):
    """
    Requirements: Testing Tool SHOULD implement (other components should not subscribe to event)

    Type: Reply (service)

    Pub/Sub: sniffing -> coordination

    Description: tbd
    """
    routing_key = "sniffing.getlastcapture.reply"

    _msg_data_template = {
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

    routing_key = "analysis.interop.testcase.analyze.request"

    _msg_data_template = {
        "protocol": "coap",
        "testcase_id": "TD_COAP_CORE_01",
        "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_01",
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
    routing_key = "analysis.interop.testcase.analyze.reply"

    _msg_data_template = {
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
        "testcase_ref": "http://doc.f-interop.eu/tests/TD_COAP_CORE_01",
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

    routing_key = "dissection.dissectcapture.request"

    _msg_data_template = {
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

    routing_key = "dissection.dissectcapture.reply"

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
        "ok": True,
        "token": "0lzzb_Bx30u8Gu-xkt1DFE1GmB4",
        "frames": _frames_example,
        "frames_simple_text": None
    }


class MsgDissectionAutoDissect(Message):
    """
    Requirements: TT MUST publish event

    Type: Event

    Pub/Sub: Testing Tool -> GUI

    Description: Used to indicate to the GUI the dissection of the exchanged packets.
        - GUI MUST display this info during execution:
            - interop session
            - conformance session
            - performance ?
            - privacy?

    """
    routing_key = "testsuite.dissection.autotriggered"

    _frames_example = MsgDissectionDissectCaptureReply._frames_example

    _msg_data_template = {
        "token": "0lzzb_Bx30u8Gu-xkt1DFE1GmB4",
        "frames": _frames_example,
        "frames_simple_text": None,
        "testcase_id": "TBD",
        "testcase_ref": "TBD"
    }

    # # # # # # PRIVACY TESTING TOOL MESSAGES # # # # # #


class MsgPrivacyAnalyze(Message):
    """
        Testing Tool's MUST-implement.
        Analyze PCAP File for Privacy checks.
    """
    routing_key = "privacy.analyze.request"

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
        "value": PCAP_COAP_GET_OVER_TUN_INTERFACE_base64,
        "file_enc": "pcap_base64",
        "filename": "TD_PRIVACY_DEMO_01.pcap",
    }


class MsgPrivacyAnalyzeReply(MsgReply):
    """
            Testing Tool's MUST-implement.
            Response of Analyze request from GUI
    """

    routing_key = 'privacy.analyze.reply'

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
        "ok": True,
        "verdict": _privacy_empty_report,
        "testcase_id": "TBD",
    }


class MsgPrivacyGetConfiguration(Message):
    """
           Read Privacy configuration.
           GUI MUST display this info during setup
    """
    routing_key = "privacy.configuration.get.request"

    _msg_data_template = {
    }


class MsgPrivacyGetConfigurationReply(MsgReply):
    """
           Read Privacy configuration.
           GUI MUST display this info during setup
    """
    routing_key = "privacy.configuration.get.reply"

    _msg_data_template = {
        "configuration": {},
        "ok": True,
    }


class MsgPrivacySetConfiguration(Message):
    """
        Write Privacy configuration.
        GUI MUST display this info during setup
    """
    routing_key = "privacy.configuration.set.request"

    CFG_EXAMPLE = dict()

    _msg_data_template = {
        "configuration": CFG_EXAMPLE,
    }


class MsgPrivacySetConfigurationReply(MsgReply):
    """
        Write Privacy configuration.
        GUI MUST display this info during setup
    """
    routing_key = 'privacy.configuration.set.reply'

    _msg_data_template = {
        "ok": True,
    }


class MsgPrivacyGetStatus(Message):
    """
    Testing Tool's MUST-implement.
    GUI -> Testing Tool
    GUI MUST display this info during execution:
     - privacy?

    """
    routing_key = "privacy.getstatus.request"

    _msg_data_template = {
    }


class MsgPrivacyGetStatusReply(MsgReply):
    """
    Testing Tool's MUST-implement.
    GUI -> Testing Tool
    GUI MUST display this info during execution:
     - privacy?

    """

    REPORT_EXAMPLE = dict()
    routing_key = "privacy.getstatus.reply"

    _msg_data_template = {
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
    routing_key = "privacy.issue"

    _msg_data_template = {
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
    routing_key = "performance.heartbeat"

    _msg_data_template = {
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
    routing_key = "performance.configuration"

    _msg_data_template = {
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
    routing_key = "performance.setvalues"

    _msg_data_template = {
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
    routing_key = "performance.stats"

    _msg_data_template = {
        "mod_name": "unknown",
        "timestamp": 0,
        "stats": {},
    }


# attention
rk_pattern_to_message_type_map = RoutingKeyToMessageMap(
    {
        # CORE API: GUI <-> SO
        "orchestrator.users.list.request": MsgOrchestratorUsersList,  # any -> SO
        "orchestrator.version.request": MsgOrchestratorVersionReq,  # any -> SO
        "orchestrator.users.add.request": MsgOrchestratorUserAdd,  # any -> SO
        "orchestrator.users.delete.request": MsgOrchestratorUserDelete,  # any -> SO
        "orchestrator.users.get.request": MsgOrchestratorUserGet,  # any -> SO
        "orchestrator.sessions.list.request": MsgOrchestratorSessionsList,  # any -> SO
        "orchestrator.sessions.get.request": MsgOrchestratorSessionsGet,  # any -> SO
        "orchestrator.sessions.add.request": MsgOrchestratorSessionsAdd,  # any -> SO
        "orchestrator.sessions.delete.request": MsgOrchestratorSessionsDelete,  # any -> SO
        "orchestrator.sessions.update.request": MsgOrchestratorSessionsUpdate,  # any -> SO
        "orchestrator.tests.get.request": MsgOrchestratorTestsGet,  # any -> SO
        "orchestrator.tests.get_contributor_name.request": MsgOrchestratorTestsGetContributorName,  # any -> SO

        # TODO deprecate this
        "orchestrator.session.created": MsgSessionCreated,  # SO -> any

        # CORE API: TT <-> GUI
        "ui.core.session.get.request": MsgUiRequestSessionConfiguration,  # TT -> GUI
        "ui.user.*.display": MsgUiDisplay,  # TT -> GUI
        "ui.user.*.request": MsgUiRequest,  # TT -> GUI
        "ui.user.*.reply": MsgUiReply,  # GUI -> TT

        # misc
        "log.*.*": MsgSessionLog,  # Any -> Any
        "log": MsgSessionLog,  # Any -> Any
        "chat": MsgSessionChat,  # GUI_x -> GUI_y

        # ioppytest API: TT <-> Agents
        "fromAgent.*.ip.tun.packet.raw": MsgPacketSniffedRaw,  # Agent -> TestingTool
        "fromAgent.*.802154.serial.packet.raw": MsgPacketSniffedRaw,  # Agent -> TestingTool
        "toAgent.*.ip.tun.packet.raw": MsgPacketInjectRaw,  # TestingTool -> Agent
        "toAgent.*.802154.serial.packet.raw": MsgPacketInjectRaw,  # TestingTool -> Agent

        "toAgent.*.ip.tun.start": MsgAgentTunStart,  # TestingTool -> Agent
        # "toAgent.*.802154.serial.start": MsgAgentSerialStart,  # TestingTool -> Agent
        "fromAgent.*.ip.tun.started": MsgAgentTunStarted,  # Agent -> TestingTool
        "fromAgent.*.802154.serial.started": MsgAgentSerialStarted,  # Agent -> TestingTool
        "fromAgent.*.configured": MsgAgentConfigured,  # TestingTool -> GUI


        # ioppytest API: TT signals
        "testingtool.ready": MsgTestingToolReady,  # Testing Tool -> GUI
        "testingtool.configured": MsgTestingToolConfigured,  # TestingTool -> Orchestrator, GUI
        "testingtool.terminate": MsgTestingToolTerminate,  # GUI, orchestrator -> TestingTool
        "testingtool.component.ready": MsgTestingToolComponentReady,  # Testing Tool internal
        "testingtool.component.shutdown": MsgTestingToolComponentShutdown,  # Testing Tool internal


        # ioppytest API: Test Suite messages (they all trigger interactions into GUI)
        "testsuite.start": MsgTestSuiteStart,  # GUI -> TestingTool
        "testsuite.started": MsgTestSuiteStarted,  # Testing Tool -> GUI
        "testsuite.finish": MsgTestSuiteFinish,  # GUI -> TestingTool
        "testsuite.testcase.ready": MsgTestCaseReady,  # TestingTool -> GUI
        "testsuite.testcase.start": MsgTestCaseStart,  # GUI -> TestingTool
        "testsuite.testcase.started": MsgTestCaseStarted,  # TestingTool -> GUI
        "testsuite.testcase.step.stimuli.execute": MsgStepStimuliExecute,  # TestingTool -> GUI
        "testsuite.testcase.step.stimuli.executed": MsgStepStimuliExecuted,  # GUI -> TestingTool
        "testsuite.testcase.step.check.execute": MsgStepCheckExecute,  # TestingTool -> GUI
        "testsuite.testcase.step.check.executed": MsgStepCheckExecuted,  # GUI -> TestingTool
        "testsuite.testcase.step.verify.execute": MsgStepVerifyExecute,  # Testing Tool Internal
        "testsuite.testcase.step.verify.executed": MsgStepVerifyExecuted,  # Testing Tool Internal
        # TODO it doesnt make much sense to have both configuration and configuration.execute
        "testsuite.testcase.configuration": MsgTestCaseConfiguration,  # TestingTool -> GUI
        "testsuite.testcase.configuration.execute": MsgConfigurationExecute,  # TestingTool -> GUI (or auto-iut)
        "testsuite.testcase.configuration.executed": MsgConfigurationExecuted,  # GUI (or auto-iut) -> TestingTool
        "testsuite.testcase.stop": MsgTestCaseStop,  # GUI -> TestingTool
        "testsuite.testcase.restart": MsgTestCaseRestart,  # GUI -> TestingTool
        "testsuite.testcase.skip": MsgTestCaseSkip,  # GUI -> TestingTool
        "testsuite.testcase.select": MsgTestCaseSelect,  # GUI -> TestingTool
        "testsuite.testcase.abort": MsgTestCaseAbort,  # GUI -> TestingTool
        "testsuite.testcase.finished": MsgTestCaseFinished,  # TestingTool -> GUI
        "testsuite.testcase.verdict": MsgTestCaseVerdict,  # TestingTool -> GUI
        "testsuite.abort": MsgTestSuiteAbort,  # GUI -> TestingTool
        "testsuite.report": MsgTestSuiteReport,  # TestingTool -> GUI
        "testsuite.dissection.autotriggered": MsgDissectionAutoDissect,  # TestingTool -> GUI

        # ioppytest testing tool: internal TT API - debugging messages
        "testsuite.status.request": MsgTestSuiteGetStatus,  # GUI -> TestingTool
        "testsuite.status.reply": MsgTestSuiteGetStatusReply,  # TestingTool -> GUI (reply)
        "testsuite.testcases.list.request": MsgTestSuiteGetTestCases,  # GUI -> TestingTool
        "testsuite.testcases.list.reply": MsgTestSuiteGetTestCasesReply,  # TestingTool -> GUI (reply)

        # TODO deprecate this (in favour of MsgUiRequestSessionConfiguration)
        "session.configuration": MsgSessionConfiguration,  # GUI-> SO -> TestingTool

        # ioppytest testing tool: internal TT API
        "sniffing.start.request": MsgSniffingStart,  # Testing Tool Internal
        "sniffing.start.reply": MsgSniffingStartReply,  # Testing Tool Internal
        "sniffing.stop.request": MsgSniffingStop,  # Testing Tool Internal
        "sniffing.stop.reply": MsgSniffingStopReply,  # Testing Tool Internal
        "sniffing.getcapture.request": MsgSniffingGetCapture,  # Testing Tool Internal
        "sniffing.getcapture.reply": MsgSniffingGetCaptureReply,  # Testing Tool Internal
        "sniffing.getlastcapture.request": MsgSniffingGetCaptureLast,  # Testing Tool Internal
        "sniffing.getlastcapture.reply": MsgSniffingGetCaptureLastReply,  # Testing Tool Internal

        "analysis.interop.testcase.analyze.request": MsgInteropTestCaseAnalyze,  # Testing Tool Internal
        "analysis.interop.testcase.analyze.reply": MsgInteropTestCaseAnalyzeReply,  # Testing Tool Internal
        "dissection.dissectcapture.request": MsgDissectionDissectCapture,  # Testing Tool Internal
        "dissection.dissectcapture.reply": MsgDissectionDissectCaptureReply,  # Testing Tool Internal

        # privacy testing tool: internal TT API
        "privacy.analyze.request": MsgPrivacyAnalyze,  # TestingTool internal
        "privacy.analyze.reply": MsgPrivacyAnalyzeReply,  # TestingTool internal (reply)
        "privacy.getstatus.request": MsgPrivacyGetStatus,  # GUI -> TestingTool
        "privacy.getstatus.reply": MsgPrivacyGetStatusReply,  # GUI -> TestingTool (reply)
        "privacy.issue": MsgPrivacyIssue,  # TestingTool -> GUI,
        "privacy.configuration.get.request": MsgPrivacyGetConfiguration,  # TestingTool -> GUI,
        "privacy.configuration.get.reply": MsgPrivacyGetConfigurationReply,  # TestingTool -> GUI (reply),
        "privacy.configuration.set.request": MsgPrivacySetConfiguration,  # GUI -> TestingTool,
        "privacy.configuration.set.reply": MsgPrivacySetConfigurationReply,  # GUI -> TestingTool (reply),

        # performance testing tool: internal TT API
        "performance.heartbeat": MsgPerformanceHeartbeat,  # Perf. Submodules -> Timeline Controller
        "performance.configuration": MsgPerformanceConfiguration,  # Orchestrator -> Timeline Controller
        "performance.stats": MsgPerformanceStats,  # Perf. Submodules -> Visualization
        "performance.setvalues": MsgPerformanceSetValues,  # Timeline Controller -> Perf. Submodules
    }
)

if __name__ == '__main__':
    # test as: python messages.py -v
    import doctest

    doctest.testmod()
