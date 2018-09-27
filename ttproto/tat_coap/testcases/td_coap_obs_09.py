from ..common import *


class TD_COAP_OBS_09(CoAPTestCase):
    """
---
TD_COAP_OBS_09:
    obj: Update of the observed resource
    cfg: CoAP_CFG_BASIC
    ref: '[OBSERVE] 4.2.3'

    pre:
        - Client supports Observe option
        - Server supports Observe option
        - "Server offers an observable resource /obs which changes periodically
        (e.g. every 5s) which produces confirmable notifications"

    seq:
    -   s: 'Client is requested to send to the server a confirmable GET
        request with observe option for resource /obs'

    -   c:
        - 'The request sent by client contains:'
        -   - Type = 0 (CON)
            - Code = 1 (GET)
            - Token value = a value generated by the client
            - Observe option = empty

    -   c:
        - 'Server sends the response containing:'
        -   - Type = 2 (ACK)
            - Code = 2.05 (Content)
            - Content-format of the resource /obs
            - Token value = same as one found in the step 2
            - Observe option with a sequence number

    -   c:
        - 'Server sends a notification containing:'
        -   - Type = 0 (CON)
            - Code = 2.05 (Content)
            - Content-format = same as one found in the step 3
            - Token value = same as one found in the step 2
            - Observe option indicating increasing values

    -   c: Client displays the received information

    -   c: Client sends an ACK

    -   s: 'Update the /obs resource of the server\u2019s resource with a new payload
            having the same Content-Format (either locally or by having another
            CoAP client perform a PUT request)'

    -   c:
        - 'Server notifications contains:'
        -   - Type = 0 (CON)
            - Code = 2.05 (Content)
            - Content-format = same as one found in the step 3
            - Token value = same as one found in the step 2
            - Observe option indicating increasing values
            - Payload = the new value sent at step 7

    -   v: Client displays the new value of /obs sent in step 8

    -   c: Client sends an ACK

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
        return [
            CoAP(type='con', code='get', opt=Opt(CoAPOptionUriPath("obs"), CoAPOptionObserve(0))),
            CoAP(type='con', code='post', opt=Opt(CoAPOptionUriPath("obs"), CoAPOptionContentFormat()))
        ]

    def run(self):
        request = CoAP(type="con", code="get", opt=self.uri("/obs", CoAPOptionObserve (0)))
        response = CoAP(type="ack", code=2.05, opt=Opt(CoAPOptionObserve(), CoAPOptionContentFormat()))

        # Step 2
        self.match("client", request)

        token = self.coap["tok"]
        uri = self.coap.get_uri()

        self.next()

        # Step 3
        if not self.match("server", response):
            raise self.Stop()
        self.match("server", CoAP(tok = token), "fail")

        content_format = self.coap["opt"][CoAPOptionContentFormat]["val"]
        index          = self.coap["opt"][CoAPOptionObserve]["val"]
        self.next()
        pl = None

        rst_sent_by_client = False

        # we need to observe at least one notification
        # (to ensure that the server is observing the resource for the client)
        notifications_received_from_server = 0

        ack_sent_by_client = 0

        # Step 4/6 and step 8/10
        while self.match("server", CoAP(type="con", code=2.05,
                        opt=Opt(CoAPOptionObserve())), None):
            self.match("server", CoAP(tok = token), "fail")
            self.match("server", CoAP(opt = Opt(CoAPOptionContentFormat(content_format))), "fail")
            new_index = self.coap["opt"][CoAPOptionObserve]["val"]
            pl = self.coap["pl"]

            self.set_verdict(("pass" if new_index > index else "fail"),
                "value of observe option must be increasing")
            self.next()
            notifications_received_from_server += 1

            # Step 6
            if self.match("client", CoAP(type="rst", code=0), None):
                rst_sent_by_client = True
                self.set_verdict("pass", "End of communication from the client.")
                self.next(True)

            # We do a while loop here if there is several following ACK in the capture.
            # It may happen sometime, e.g because of latency.
            if self.match("client", CoAP(type="ack", code=0), None):
                ack_sent_by_client += 1
                self.set_verdict("pass", "ACK from client.")
                self.next(True)

            #self.next()
            stimulis = self.__check_stimulis(content_format)

        # TODO Check which code to check to throw the error.
        if self.match("server", CoAP(type="con", tok = token, code=Any(134,160,140,143)), None):
            self.set_verdict("fail", "Server sent an error (decimal code = %d) to the client." % self.coap['code'])
        else:
            self.set_verdict("pass", "Server did not send error to the client after payload changed.")
        if notifications_received_from_server < 1:
            self.set_verdict("inconclusive", "Only one notification since the beginning of the test.\
            Unable to perform the check at step 8.")

        delta = notifications_received_from_server - ack_sent_by_client
        if delta == 0:
            self.set_verdict("pass", "Every notifications has been acknoledged.")
        elif delta == 1 and rst_sent_by_client:
            self.set_verdict("pass", "Every notifications has been acknoledged. \
excepted the last one as the client terminated the test session properly with an RST.")
        raise self.Stop()

    def __check_stimulis(self, content_format:str)->bool:
        # Step 7: Stimulus. This step is optional as changing the Content-Format
        # may be done internally by the server.
        # return a boolean that determine if we encountered this optional stimulis
        stimulis = False
        if self.match("client", CoAP(type='con', code='post', opt=Opt(CoAPOptionUriPath("obs"), CoAPOptionContentFormat())), None):
            new_content_format = self.coap["opt"][CoAPOptionContentFormat]["val"]
            self.set_verdict(("pass" if new_content_format == content_format
                else "inconclusive"),"Stimulus: POST performed with the same Content-Format.\
                If the POST is performed with another Content-Format, we have\
                no way to check the behavior of this TC")
            stimulis = True
            self.next()

        if self.match("server", CoAP(type="ack", code=2.04), None):
            self.set_verdict("pass", "Stimulus: Confirmation from server that POST suceeded with the same Content-Format")
            self.next()
            stimulis = True

        return stimulis