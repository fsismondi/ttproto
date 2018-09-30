import os
import unittest
from ttproto.tat_coap.common import CoAPTestCase
from ttproto.core.dissector import Capture
from ttproto.tat_coap.testcases.td_coap_core_04 import TD_COAP_CORE_04
from ttproto.tat_coap.testcases.td_coap_core_09 import TD_COAP_CORE_09
from ttproto.tat_coap.testcases.td_coap_obs_07 import TD_COAP_OBS_07
from ttproto.core.analyzer import Conversation
# from ttproto.core.lib.inet.coap import *
from ttproto.core.lib.inet.udp import UDP
from ttproto.tat_coap.templates import CoAP, CoAPOptionUriPath
from ttproto.core.typecheck import typecheck


class TestCommon(unittest.TestCase):

    def __get_capture(self,
                      pcap_file,
                      dir_from_test_dumps="coap_observe"):
        pcap_dir_path = os.path.dirname(os.path.abspath(__file__))
        pcap_dir_path = os.path.join(pcap_dir_path,
                                     os.path.join('../test_dumps/'
                                                  , dir_from_test_dumps)
                                     )
        return Capture(os.path.join(pcap_dir_path, pcap_file))

    def __get_convs(self,
                    pcap_file:str,
                    dir_from_test_dumps='preprocess/coap'):
        capture = self.__get_capture(pcap_file, dir_from_test_dumps)
        convs, ignored = CoAPTestCase.extract_all_coap_conversations(capture)
        return convs, ignored

    def test_conv_with_no_token(self):
        convs, ignored = self.__get_convs('Single_conversation_empty_token.pcap')
        assert len(convs) == 1
        self.__check_single_conv_no_token(convs[0])

    def test_convs_with_token(self):
        convs, ignored = self.__get_convs('Two_conversations_two_tokens.pcap')
        assert len(convs) == 2

        # For each conversation, we want to check that all packets have the same
        # token. However, we do ignore token in case of ACK packet as those do
        # not have token value.
        # We still check that the CMID of the ACK is a CMID of a frame with the
        # current conversation token to verify that this ACK really belong to it.
        for conv in convs:
            self.__check_single_conv_with_token(conv)

    def test_convs_mixed(self):
        convs, ignored = self.__get_convs('Two_conversations_one_token.pcap')
        assert len(convs) == 2
        self.__check_single_conv_no_token(convs[0])
        self.__check_single_conv_with_token(convs[1])

    def test_conv_with_RST(self):
        capture = self.__get_capture('TD_COAP_OBS_06_PASS_One_Con_before_RST.pcap')
        convs, ignored = CoAPTestCase.extract_all_coap_conversations(capture)

        # We want only one conversation here : The last packet, containing the
        # RST, belong to the same conversation of all previous packets in the
        # capture TD_COAP_OBS_06_PASS_One_Con_before_RST.pcap.
        # It is because the RST has the same an MID as the last packet
        # sent by the server, hence the RST belong to the same conversation
        # described by the token of this last packet
        assert len(convs) == 1

    def __check_single_conv_with_token(self, conv):
        first_frame = conv[0]
        current_conversation_CTOK = first_frame[CoAP]["tok"]
        CMID = first_frame[CoAP]['mid']

        # The set of encountered CMID in this conversation.
        # When we see an ACK, the CMID of this ACK must be already present
        # in this set. If its not the case, it means that this ACK should
        # not belong in this conversation.
        CMIDs = set()
        # CMIDs.add(CMID)

        for frame in conv:
            current_frame_CTOK = frame[CoAP]["tok"]

            if current_frame_CTOK == b'':
                # ACK do not have a token and are solely based on message ID.
                # For this TC, empty token are acceptable only for ACK.
                assert frame[CoAP]['type'] == 2
                assert frame[CoAP]['mid'] in CMIDs
            else:
                assert current_frame_CTOK == current_conversation_CTOK
                CMID = frame[CoAP]['mid']
                # assert CMID not in CMIDs
                CMIDs.add(CMID)

    def __check_single_conv_no_token(self, conv):
        # The set of encountered CMID in this conversation.
        # When we see an ACK, the CMID of this ACK must be already present
        # in this set. If its not the case, it means that this ACK should
        # not belong in this conversation.
        CMIDs = set()

        for frame in conv:
            current_frame_CTOK = frame[CoAP]["tok"]
            assert current_frame_CTOK == b''
            if frame[CoAP]['type'] == 2:
                assert frame[CoAP]['mid'] in CMIDs
            else:
                CMID = frame[CoAP]['mid']
                # assert CMID not in CMIDs
                CMIDs.add(CMID)

    def test_conv_correlation_into_single_conv(self):
        capture = self.__get_capture('TD_COAP_OBS_07_PASS_With_202_Deleted_delayed.pcap')
        convs, ignored = CoAPTestCase.extract_all_coap_conversations(capture)
        # We await 2 conversations : One for the observing client on /obs,
        # one for another client doing a DELETE request on /obs.
        assert len(convs) == 2
        conv_obs_client = convs[0]
        assert len(convs[0]) == 8  # All the frame of the observing client.
        assert conv_obs_client[0][CoAP]["opt"][CoAPOptionUriPath]['val'] == 'obs'
        assert conv_obs_client[6][CoAP]['code'] == 132

        # The conversation of the client doing a DELETE req has only 2 frames
        # in the pcap :
        assert len(convs[1]) == 2
        conv_del_client = convs[1]
        # The delete request on /obs...
        assert conv_del_client[0][CoAP]['code'] == 4
        assert conv_del_client[0][CoAP]["opt"][CoAPOptionUriPath]['val'] == 'obs'
        # ...and the 2.02 DELETED confirmation from the server.
        assert conv_del_client[1][CoAP]['code'] == 66

        correlated_conv = CoAPTestCase.correlate(convs,
                                                 TD_COAP_OBS_07.get_stimulis()
                                                 )[0]
        assert len(correlated_conv) == 10
        for i in range(0, 5):
            # Before the stimulis of the second client (doing delete) happen,
            # The frames of the correlated conv are identical with the frames of
            # the conversation of the first client (doing get).
            assert correlated_conv[i][CoAP] == conv_obs_client[i][CoAP]

        # The second stimulis of the second client start here.
        # We check we managed properly some reordering here :
        # We want to have the confirmation "2.02 DELETED" sent to the second
        # client right after his DELETE request and before the "4.04 Not Found"
        # sent to the first client. Even if it's not  necessary the case in the
        # original pcap.

        # We also check that the stimulus frame of the second client is
        # still the seventh, as we're supposed to add the frames of the second
        # conversation into the correlated one as soon as we encounter it's
        # first stimulis.

        assert correlated_conv[6][CoAP]['code'] == 4 # Frame 7 - conversation 2
        assert correlated_conv[7][CoAP]['code'] == 66 # Frame 8 - conversation 2
        assert correlated_conv[7][CoAP]['type'] == 2

        assert correlated_conv[8][CoAP]['code'] == 132 # From conversation 1
        assert correlated_conv[9][CoAP]['mid'] == correlated_conv[8][CoAP]['mid']

    def test_conv_correlation_with_unrealated_conv_in_pcap(self):
        capture = self.__get_capture('OBS_07_with_other_unrelated_convs.pcap',
                                     dir_from_test_dumps='preprocess/coap')
        convs, ignored = CoAPTestCase.extract_all_coap_conversations(capture)

        # We await 2 conversations : One for the observing client on /obs, one for
        # another client doing a DELETE request on /obs, and 3 others unrealated
        # conversations (GET and POST on /test).
        assert len(convs) == 5

        all_correlated_convs = CoAPTestCase.correlate(convs,
                                                      TD_COAP_OBS_07.get_stimulis())
        # There is only that can realisticly match one instance of OBS_07 in the
        # pcap.
        assert len(all_correlated_convs) == 1
        # Those 8 frames are related to the TC.
        correlated_conv = all_correlated_convs[0]
        assert len(correlated_conv) == 8
        assert correlated_conv[0][CoAP]["opt"][CoAPOptionUriPath]['val'] == 'obs'

        # The delete request on /obs. It now the 5th frame and not the 9th like
        # in the original capture as 4 frames related to some core TC has been
        # filtered.
        assert correlated_conv[4][CoAP]['code'] == 4
        assert correlated_conv[4][CoAP]["opt"][CoAPOptionUriPath]['val'] == 'obs'
        # ...and the 2.02 DELETED confirmation from the server.
        # Because of reordering, it's right after the deletion request.
        assert correlated_conv[5][CoAP]['code'] == 66

        # 4.04 not found.
        assert correlated_conv[6][CoAP]['code'] == 132
        # Ack from client.
        assert correlated_conv[7][CoAP]['mid'] == correlated_conv[6][CoAP]['mid']

    def test_severals_convs_for_tc_in_single_pcap(self):
        capture = self.__get_capture('Two_tc_two_times_each_with_overlap.pcap',
                                     dir_from_test_dumps='preprocess/coap')
        conversations, ignored = CoAPTestCase.extract_all_coap_conversations(capture)
        assert len(conversations) == 4

        # A normal conversation of CORE 09 (separate response) is one get, one ack
        # from server, one notification (2.05 content) from server later and then
        # one ack from client for this notification.
        # Hence 2 conversation and 8 frames are expected (4 per conversation)
        # as the pcap contains two occurences of COAP_CORE_09 scenario.
        conversations_tc_09 = CoAPTestCase.correlate(
                                                conversations,
                                                TD_COAP_CORE_09.get_stimulis()
                                                    )
        # The pcap contains two correlated conversations related to CORE_09.
        assert len(conversations_tc_09) == 2

        assert len(conversations_tc_09[0]) == 4,\
            "expected 4 frames , but got %s " % len(conversations_tc_09[0])
        self.__check_conv_is_tc_09(conversations_tc_09[0])
        assert len(conversations_tc_09[1]) == 4,\
            "expected 4 frames , but got %s " % len(conversations_tc_09[1])
        self.__check_conv_is_tc_09(conversations_tc_09[1])

        # A normal conversation of CORE 04 is a simple POST with a 2.01 created
        # or a 2.04 changed response from the server. We have those two packets
        # for one execution of this case.
        # We did execute two times the stimulis in the given pcap, hence
        # 2 conversations and 4 frames are expected (2 per conversation).
        conversations_tc_04 = CoAPTestCase.correlate(
                                                conversations,
                                                TD_COAP_CORE_04.get_stimulis()
                                                    )
        assert len(conversations_tc_04) == 2,\
            "expected 2 conversations , but got %s " % len(conversations_tc_04)

        self.__check_conv_is_tc_04(conversations_tc_04[0])
        assert len(conversations_tc_04[1]) == 2,\
            "expected 2 frames , but got %s " % len(conversations_tc_04[0])

        self.__check_conv_is_tc_04(conversations_tc_04[1])
        assert len(conversations_tc_04[1]) == 2,\
            "expected 2 frames , but got %s " % len(conversations_tc_04[1])

    @classmethod
    @typecheck
    def __check_conv_is_tc_09(self, conv: Conversation):
        token = conv[0][CoAP]['tok']
        assert conv[0][CoAP]['code'] == 1
        assert conv[0][CoAP]["opt"][CoAPOptionUriPath]['val'] == 'separate'
        # print(conv[0][CoAP])
        # assert conv[0][CoAP].match(CoAP(type='con'))
        assert conv[1][CoAP]['type'] == 2
        assert conv[1][CoAP]['code'] == 0
        assert conv[1][UDP]['sport'] == 5683
        assert conv[2][CoAP]['code'] == 69
        assert conv[2][CoAP]['tok'] == token
        assert conv[2][UDP]['sport'] == 5683

        assert conv[3][CoAP]['type'] == 2
        assert conv[3][CoAP]['code'] == 0
        assert conv[3][UDP]['dport'] == 5683

    @classmethod
    @typecheck
    def __check_conv_is_tc_04(self, conv: Conversation):
        token = conv[0][CoAP]['tok']
        assert conv[0][CoAP]['code'] == 2
        assert conv[0][CoAP]["opt"][CoAPOptionUriPath]['val'] == 'test'

        assert conv[1][UDP]['sport'] == 5683
        assert conv[1][CoAP]['tok'] == token
        assert conv[1][CoAP]['type'] == 2
        assert conv[1][CoAP]['code'] == 65 # 2.01 Created
        assert conv[1][CoAP]["opt"][0]['val'] == 'location1'
        assert conv[1][CoAP]["opt"][1]['val'] == 'location2'
        assert conv[1][CoAP]["opt"][2]['val'] == 'location3'

    @classmethod
    @typecheck
    def __pprint_coap_conversation(cls, conv:Conversation):
        cls.__pprint_conversation(conv, 5683)

    @classmethod
    @typecheck
    def __pprint_conversation(cls, conv:Conversation, server_port_number:int):
        """
        print the given conversation with more detail about the presence of
        several differents sub-conversations contained inside (e.g several clients)
        It also show clearer the source and destination of Frame as "Client" and
        "Server" instead of IP addresses.
        """
        # TODO Probably relevant to move this method elsewhere. Maybe as class
        # method of Conversation
        conv_src_ports_to_conv_number = dict()
        print('\n')
        last_conv_num = -1
        for frame in conv:
            frameStr = str(frame)
            if frame[UDP]['sport'] != server_port_number:
                client_port = frame[UDP]['sport']
                server_ip = frameStr[frameStr.index('[')+1:frameStr.index('->')-1]
                client_ip = frameStr[frameStr.index('->')+3:frameStr.index(']')]
            else:
                client_port = frame[UDP]['dport']
                client_ip = frameStr[frameStr.index('[')+1:frameStr.index('->')-1]
                server_ip = frameStr[frameStr.index('->')+3:frameStr.index(']')]

            conv_number = conv_src_ports_to_conv_number.get(client_port)
            new_conversation = False
            if conv_number is None:
                conv_number = len(conv_src_ports_to_conv_number.keys()) + 1
                conv_src_ports_to_conv_number[client_port] = conv_number
                new_conversation = True

            if conv_number != last_conv_num:
                if last_conv_num != -1:
                    print("============== Next packet is not in conversation " + str(last_conv_num) + " ==============" +'\n')
                if not new_conversation:
                    print("============== In conversation " + str(conv_number)+ " once again ==============")
                else:
                    print("============== Begin  of conversation " + str(conv_number)+ " ==============")

            if (frame[UDP]['sport'] == server_port_number):
                client_port = frame[UDP]['dport']
                conv_number = conv_src_ports_to_conv_number[client_port]
                frameStr = frameStr.replace(server_ip + " ->", "Server ->")
                frameStr = frameStr.replace("-> " + client_ip, "-> Client " + str(conv_number))
            else:
                client_port = frame[UDP]['sport']
                conv_number = conv_src_ports_to_conv_number[client_port]
                frameStr = frameStr.replace(client_ip + " ->", "Client "  + str(conv_number) + " ->")
                frameStr = frameStr.replace("-> " + server_ip, "-> Server")
            print(frameStr + '\n')
            last_conv_num = conv_number

        print("============== End of conversation " + str(conv_number) + " ==============" +'\n')
