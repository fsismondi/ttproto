#!/usr/bin/env python3
from ..common import *


class TD_COAP_CORE_18(CoAPTestCase):
    """
---
TD_COAP_CORE_18:
    cfg: CoAP_CFG_BASIC
    obj: Perform POST transaction with responses containing several
         Location-Path options (CON mode)
    pre: Server accepts creation of new resource on /test and the created
        resource is located at /location1/location2/location3 (resource
        does not exist yet)
    ref: '[COAP] 5.8.1, 5.10.8, 5.9.1.1'
    seq:
    -   s: "Client is requested to send a confirmable POST request to server\
            \u2019s resource"
    -   c:
        - 'The request sent by the client contains:'
        -   - Type = 0 (CON
            - Code = 2 (POST)
            - An arbitrary payload
            - Content-format option
            - Uri-Path option "test"
    -   c:
        - 'Server sends response containing:'
        -   - Code = 2.01 (Created)
        - 'and three options of type Location-Path, with the values (none
            of which contains a "/"):'
        -   - location1
            - location2
            - location3
    -   v: Client displays the response
    """

    @classmethod
    @typecheck
    def get_stimulis(cls) -> list_of(Value):
        """
        Get the stimulis of this test case. This has to be be implemented into
        each test cases class.

        :return: The stimulis of this TC
        :rtype: [Value]

        .. note::
            Check the number/value of the uri query options or not?
        """
        return [
            CoAP(type='con', code='post', opt=Opt(CoAPOptionUriPath("test")))
        ]

    request_uri = "/test"

    def run(self):
        self.match("client", CoAP(type="con",
                                  code="post",
                                  pl=Not(b""),
                                  opt=self.uri(
                                      self.request_uri,
                                      CoAPOptionContentFormat(),
                                  )))

        self.next_skip_ack()
        # TODO: generate a fail if we have a '/' or '.' or '..' in the CoAPOptionLocationPath ? see 5.10.7
        self.match("server", CoAP(code=2.01,
                                  opt=Opt(
                                      CoAPOptionLocationPath("location1"),
                                      CoAPOptionLocationPath("location2"),
                                      CoAPOptionLocationPath("location3"),
                                  )))

        self.next_skip_ack(optional=True)
