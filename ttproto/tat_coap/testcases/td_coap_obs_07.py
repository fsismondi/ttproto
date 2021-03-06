from ..common import *


class TD_COAP_OBS_07(CoAPTestCase):
    """
---
TD_COAP_OBS_07:
    obj: Server cleans the observers list on DELETE
    cfg: CoAP_CFG_BASIC
    ref: 3.2.4
    pre:
        - Client supports Observe option
        - Server supports Observe option
        - "Server offers an observable resource /obs which changes periodically (e.g. every
        5s) which produces confirmable notifications"

    seq:
    -   s: "Client is requested to send to the server a confirmable GET
            request with observe option for resource /obs"

    -   c:
        - The request sent by client contains:
        -   - Type = 0 (CON)
            - Code = 1 (GET)
            - Token value  = a value generated by the client
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


    -   c:
        - Client displays the received information

    -   c:
        - Client sends an ACK

    -   s: "Delete the /obs resource of the server (either locally or by
        having another CoAP client perform a DELETE request)"

    -   c:
        - 'Server sends a notification containing:'
        -   - Type = 0 (CON)
            - Code = 132 (4.04 NOT FOUND)
            - Token value = same as one found in the step 2
            - No Observe option any more

    -   v: Server does not send further responses

    -   v: Client does not display further received information

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
            CoAP(type='con', code='get', opt=Opt(CoAPOptionObserve(0),CoAPOptionUriPath("obs"))),
            CoAP(type="con", code="delete", opt=Opt(CoAPOptionUriPath("obs"))),
        ]


    def run(self):
        request = CoAP(type="con", code="get",	opt=self.uri("/obs", CoAPOptionObserve(0)))
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

        # we need to observe at least one notification
        # (to ensure that the server is observing the resource for the client)

        verdict_if_none = "inconclusive"

        # Step 4
        while self.match("server", CoAP(type="con", code=2.05, opt=Opt (CoAPOptionObserve())),
            verdict_if_none):

            self.match("server", CoAP(tok = token), "fail")
            self.match("server", CoAP(opt = Opt (CoAPOptionContentFormat (content_format))), "fail")

            new_index = self.coap["opt"][CoAPOptionObserve]["val"]

            self.set_verdict(("pass" if new_index > index else "fail"),
            "value of observe option must be increasing")

            self.next()

            # Step 6
            self.match("client", CoAP (type="ack", code=0))

            self.next()

            # now we have successfully observed a observe response
            verdict_if_none = None

        # As we use UDP and we have two clients (one observing, another deleting),
        # We have no guarantee on which order will the packets arrive.
        # Hence we rely on the CMID to check the step 8.
        CMID_delete_request = None

        # Step 7
        if self.match("client", CoAP(type="con", code="delete"),
            None):

            self.set_verdict("pass" if uri == self.coap.get_uri() else "inconclusive",
                "deleted resource should be the observed resource (%s)" % uri)

            CMID_delete_request = self.coap["mid"]
            self.next()

        client_has_been_notified = False
        # Optional as the stimuli may be done internally by the server, as
        # stated by step 7.
        server_has_confirmed_deletion = False
        sent_notif_after_deletion = False

        while (client_has_been_notified is False and
            Not(CoAP(type="con", code=4.04, opt = NoOpt(CoAPOptionObserve())))
            and not sent_notif_after_deletion):
            if (self.coap["mid"] == CMID_delete_request):
                if self.match("server", CoAP(type="ack", code=2.02)):
                    server_has_confirmed_deletion = True
                self.next()
            # Step 8 - PASS case
            if self.match("server", CoAP(type="con", code=4.04, opt = NoOpt(CoAPOptionObserve())), None):
                self.match("server", CoAP(tok = token), "fail")
                client_has_been_notified = True
                self.next()
                self.match("client", CoAP(type="ack", code=0)) # Step 9

            if self.match("server", CoAP(type="con", code=2.05, opt=Opt (CoAPOptionObserve())),None):
                # Step 8 - FAIL case
                if server_has_confirmed_deletion:
                    sent_notif_after_deletion = True
                    self.set_verdict("fail", "Step 8-9: The server continued \
to send notification after it's confirmed the deletion of the resource")
                    self.next()
                else:
                    # Step 8 - INCONCLUSIVE case
                    if CMID_delete_request is not None: #i.e stimulus not done locally.
                        sent_notif_after_deletion = True
                        self.set_verdict("inconclusive", "The DELETE stimulis \
is present but there is no confirmation from the server (2.02 DELETED),\n nor 4.04\
 NOT FOUND sent to the observing client. Cannot determine if the stimulis was\
 actually executed.")
                        self.next()
                while self.match("server", CoAP(type="con", code=2.05, opt=Opt (CoAPOptionObserve())),
                None):
                    self.set_verdict("fail", "Step 8-9: The server continued\
 to send notification after it's confirmed the deletion of the resource")
                    self.next()
