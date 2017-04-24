import socket, logging, platform, os, subprocess, time, sys, argparse, threading
from ttproto.core.data  import *
from ttproto.core.lib.all   import *

logger = logging.getLogger(__name__)

"""
PRECONDITIONS:
- Have a running CoAP server at 127.0.0.1:5683, with the /resurces configured in TD_COAP ETSI doc.
- have tcpdump installed
"""

IP='127.0.0.1'
UDP_PORT=5683

def _launch_sniffer(filename, filter_if = None):
    logger.info('Launching packet capture..')

    if (filter_if is None) or (filter_if == ''):
        sys_type = platform.system()
        if sys_type == 'Darwin':
            filter_if = 'lo0'
        else:
            filter_if = 'lo'
    logger.info('logging in %s' % filter_if)
            # TODO windows?

    # lets try to remove the filemame in case there's a previous execution of the TC
    try:
        params = 'rm ' + filename
        os.system(params)
    except:
        pass

    params = 'tcpdump  -K -i ' + filter_if + ' -s 200 ' + ' -U -w ' + filename + ' udp -vv ' + '&'
    os.system(params)
    logger.info('creating process tcpdump with: %s' % params)
    # TODO we need to catch tcpdump: <<tun0: No such device exists>> from stderr

    return True


def _stop_sniffer():
    proc = subprocess.Popen(["pkill", "-INT", "tcpdump"], stdout=subprocess.PIPE)
    proc.wait()
    logger.info('Packet capture stopped')
    return True

def default_PASS_client_emulator(type, code, mid, token, payload ,option):
    coap_msg =  CoAP(type=type, code=code, mid=mid, tok=token, pl=payload, opt=option)
    #coap_msg = CoAP(type='con', code='get')
    print('***** CLIENT What we send : *****')
    print(coap_msg)
    msg, msg_bytes = coap_msg.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.sendto(msg_bytes, (IP,UDP_PORT))
    #receive message
    reply = sock.recv(1024)
    #translate message
    binary_msg = Message(reply, CoAP)
    coap_message = binary_msg.get_value()
    print('***** CLIENT What we receive : *****')
    print(coap_message)
    sock.close()

def td_coap_core_01_PASS_client_emulator():
    default_PASS_client_emulator('con', 'get', 9, 1, 'test payload client', CoAPOptionList([CoAPOptionUriPath ("test_option_client")]))


def td_coap_core_01_PASS_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    #build response
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05, pl='test payload server', opt= CoAPOptionList([CoAPOptionUriPath ("test"),CoAPOptionContentFormat(3)] ))
    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

#fail : no opt CoAPOptionContentFormat(3)
def td_coap_core_01_FAIL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    # print(addr[0])
    # print(addr[1])
    # print(coap_message['mid'])
    #build response
    #fail : no opt CoAPOptionContentFormat(3)
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05, pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionUriPath("test")]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()


def td_coap_core_02_PASS_client_emulator():
    default_PASS_client_emulator('con', 'delete', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath("test_option_client")]))

def td_coap_core_02_PASS_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    #build response
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.02, pl='test payload server', opt= CoAPOptionList([CoAPOptionUriPath ("test"),CoAPOptionContentFormat(3)] ))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_02_FAIL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    # print(addr[0])
    # print(addr[1])
    # print(coap_message['mid'])
    #build response
    #fail : no opt CoAPOptionContentFormat(3)
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.02, pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionUriPath("test")]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_03_PASS_client_emulator():
    default_PASS_client_emulator('con', 'put', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath("test_option_client"),CoAPOptionContentFormat(3)]))

def td_coap_core_03_FAIL_client_emulator():
    # fail : no opt CoAPOptionContentFormat(3)
    default_PASS_client_emulator('con', 'put', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath("test_option_client")]))

def td_coap_core_03_PASS_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    #build response
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.04, pl='test payload server', opt=CoAPOptionList([CoAPOptionUriPath ("test option server"),CoAPOptionContentFormat(3)]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_03_PASS_NO_PL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    #build response
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.04)

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_03_FAIL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    #build response
    #fail : no opt CoAPOptionContentFormat(3)
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.04, pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionUriPath("test option server")]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_04_PASS_client_emulator():
    default_PASS_client_emulator('con', 'post', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath("test_option_client"),CoAPOptionContentFormat(3)]))

def td_coap_core_04_FAIL_client_emulator():
    # fail : no opt CoAPOptionContentFormat(3)
    default_PASS_client_emulator('con', 'post', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath("test_option_client")]))

def td_coap_core_04_PASS_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    #build response
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.04, pl='test payload server', opt=CoAPOptionList([CoAPOptionUriPath ("test option server"),CoAPOptionContentFormat(3)]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_04_PASS_NO_PL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    #build response
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.04)

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_04_FAIL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    # print(addr[0])
    # print(addr[1])
    # print(coap_message['mid'])
    #build response
    #fail : no opt CoAPOptionContentFormat(3)
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.04, pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionUriPath("test option server")]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_05_PASS_client_emulator():
    default_PASS_client_emulator('non', 'get', 9, 1, 'test payload client', CoAPOptionList([CoAPOptionUriPath("test_option_client"),CoAPOptionContentFormat(3)]))

def td_coap_core_05_PASS_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    #build response
    coap_response = CoAP(type='non', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05, pl='test payload server', opt=CoAPOptionList([CoAPOptionUriPath ("test option server"),CoAPOptionContentFormat(3)]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_05_FAIL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    # print(addr[0])
    # print(addr[1])
    # print(coap_message['mid'])
    #build response
    #fail : no opt CoAPOptionContentFormat(3)
    coap_response = CoAP(type='non', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05, pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionUriPath("test option server")]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_06_PASS_client_emulator():
    default_PASS_client_emulator('non', 'delete', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath("test_option_client"), CoAPOptionContentFormat(3)]))

def td_coap_core_06_PASS_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    #build response
    coap_response = CoAP(type='non', mid=coap_message['mid'], tok=coap_message['tok'], code=2.02, pl='test payload server', opt=CoAPOptionList([CoAPOptionUriPath ("test option server"),CoAPOptionContentFormat(3)]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_06_PASS_NO_PL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    #build response
    coap_response = CoAP(type='non', mid=coap_message['mid'], tok=coap_message['tok'], code=2.02)

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_06_FAIL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    # print(addr[0])
    # print(addr[1])
    # print(coap_message['mid'])
    #build response
    #fail : no opt CoAPOptionContentFormat(3)
    coap_response = CoAP(type='non', mid=coap_message['mid'], tok=coap_message['tok'], code=2.02, pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionUriPath("test option server")]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_07_PASS_client_emulator():
    default_PASS_client_emulator('non', 'put', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath("test_option_client"), CoAPOptionContentFormat(3)]))

def td_coap_core_07_FAIL_NO_PL_client_emulator():
    default_PASS_client_emulator('non', 'put', 9, 1, '',
                                 CoAPOptionList([CoAPOptionUriPath("test_option_client"), CoAPOptionContentFormat(3)]))

def td_coap_core_07_FAIL_NO_OPT_client_emulator():
    default_PASS_client_emulator('non', 'put', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath("test_option_client")]))

def td_coap_core_07_PASS_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    #build response
    coap_response = CoAP(type='non', mid=coap_message['mid'], tok=coap_message['tok'], code=2.04, pl='test payload server', opt=CoAPOptionList([CoAPOptionUriPath ("test option server"),CoAPOptionContentFormat(3)]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_07_PASS_NO_PL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    #build response
    coap_response = CoAP(type='non', mid=coap_message['mid'], tok=coap_message['tok'], code=2.04)

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_07_FAIL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    # print(addr[0])
    # print(addr[1])
    # print(coap_message['mid'])
    #build response
    #fail : no opt CoAPOptionContentFormat(3)
    coap_response = CoAP(type='non', mid=coap_message['mid'], tok=coap_message['tok'], code=2.04, pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionUriPath("test option server")]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_08_PASS_client_emulator():
    default_PASS_client_emulator('non', 'post', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath("test_option_client"), CoAPOptionContentFormat(3)]))

def td_coap_core_08_FAIL_NO_PL_client_emulator():
    default_PASS_client_emulator('non', 'post', 9, 1, '',
                                 CoAPOptionList([CoAPOptionUriPath("test_option_client"), CoAPOptionContentFormat(3)]))

def td_coap_core_08_FAIL_NO_OPT_client_emulator():
    default_PASS_client_emulator('non', 'post', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath("test_option_client")]))

def td_coap_core_08_PASS_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    #build response
    coap_response = CoAP(type='non', mid=coap_message['mid'], tok=coap_message['tok'], code=2.04, pl='test payload server', opt=CoAPOptionList([CoAPOptionUriPath ("test option server"),CoAPOptionContentFormat(3)]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_08_PASS_NO_PL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    #build response
    coap_response = CoAP(type='non', mid=coap_message['mid'], tok=coap_message['tok'], code=2.04)

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_08_FAIL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    # print(addr[0])
    # print(addr[1])
    # print(coap_message['mid'])
    #build response
    #fail : no opt CoAPOptionContentFormat(3)
    coap_response = CoAP(type='non', mid=coap_message['mid'], tok=coap_message['tok'], code=2.04, pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionUriPath("test option server")]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_09_PASS_client_emulator():
    coap_msg =  CoAP(type='con', code='get', mid=9, tok=1, pl='test payload client', opt=CoAPOptionList([CoAPOptionUriPath ("test option client"),CoAPOptionContentFormat(3)]))
    print('***** CLIENT What we send : *****')
    print(coap_msg)
    msg, msg_bytes = coap_msg.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.sendto(msg_bytes, (IP,UDP_PORT))

    # receive acknowledgment
    ack_recev = sock.recv(1024)
    # translate acknowledgment
    binary_msg_ack = Message(ack_recev, CoAP)
    coap_ack_recv = binary_msg_ack.get_value()
    print('***** CLIENT acknowledgment receive : *****')
    print(coap_ack_recv)

    #receive message
    reply = sock.recv(1024)
    #translate message
    binary_msg = Message(reply, CoAP)
    coap_message = binary_msg.get_value()
    print('***** CLIENT What we receive : *****')
    print(coap_message)

    # build ack
    ack = CoAP(type='ack', mid=coap_message['mid'], code=0)
    print('***** CLIENT send acknowledgment : *****')
    print(ack)
    # send acknowledgment
    msg, msg_bytes_ack = ack.build_message()
    sock.sendto(msg_bytes_ack, (IP, UDP_PORT))

    sock.close()

    return reply

def td_coap_core_09_PASS_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, UDP_PORT))
    msg_recv, addr = sock.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)

    #build ack
    ack = CoAP(type='ack', mid=coap_message['mid'], code=0)
    print('***** SERVER send acknowledgment : *****')
    print(ack)
    # send acknowledgment
    msg, msg_bytes_ack = ack.build_message()
    sock.sendto(msg_bytes_ack, (addr[0], addr[1]))

    time.sleep(2)
    #build response
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05, pl='test payload server', opt=CoAPOptionList([CoAPOptionUriPath ("test option server"),CoAPOptionContentFormat(3)]))
    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    sock.sendto(msg_bytes, (addr[0], addr[1]))

    # receive acknowledgment
    msg_ack_recv, addr = sock.recvfrom(1024)
    # translate acknowledgment
    binary_msg_ack = Message(msg_ack_recv, CoAP)
    coap_ack_recv = binary_msg_ack.get_value()
    print('***** SERVER acknowledgment receive : *****')
    print(coap_ack_recv)

    sock.close()

def td_coap_core_09_FAIL_NO_OPT_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, UDP_PORT))
    msg_recv, addr = sock.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)

    #build ack
    ack = CoAP(type='ack', mid=coap_message['mid'], code=0)
    print('***** SERVER send acknowledgment : *****')
    print(ack)
    # send acknowledgment
    msg, msg_bytes_ack = ack.build_message()
    sock.sendto(msg_bytes_ack, (addr[0], addr[1]))

    time.sleep(2)
    #build response
    # fail : no opt CoAPOptionContentFormat(3)
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05, pl='test payload server', opt=CoAPOptionList([CoAPOptionUriPath ("test option server")]))
    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    sock.sendto(msg_bytes, (addr[0], addr[1]))

    # receive acknowledgment
    msg_ack_recv, addr = sock.recvfrom(1024)
    # translate acknowledgment
    binary_msg_ack = Message(msg_ack_recv, CoAP)
    coap_ack_recv = binary_msg_ack.get_value()
    print('***** SERVER acknowledgment receive : *****')
    print(coap_ack_recv)

    sock.close()

def td_coap_core_09_FAIL_NO_PL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, UDP_PORT))
    msg_recv, addr = sock.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)

    #build ack
    ack = CoAP(type='ack', mid=coap_message['mid'], code=0)
    print('***** SERVER send acknowledgment : *****')
    print(ack)
    # send acknowledgment
    msg, msg_bytes_ack = ack.build_message()
    sock.sendto(msg_bytes_ack, (addr[0], addr[1]))

    time.sleep(2)
    #build response
    # fail : no opt CoAPOptionContentFormat(3)
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05, opt=CoAPOptionList([CoAPOptionUriPath ("test option server"),CoAPOptionContentFormat(3)]))
    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    sock.sendto(msg_bytes, (addr[0], addr[1]))

    # receive acknowledgment
    msg_ack_recv, addr = sock.recvfrom(1024)
    # translate acknowledgment
    binary_msg_ack = Message(msg_ack_recv, CoAP)
    coap_ack_recv = binary_msg_ack.get_value()
    print('***** SERVER acknowledgment receive : *****')
    print(coap_ack_recv)

    sock.close()

def td_coap_core_09_FAIL_NO_TOK_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, UDP_PORT))
    msg_recv, addr = sock.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)

    #build ack
    ack = CoAP(type='ack', mid=coap_message['mid'], code=0)
    print('***** SERVER send acknowledgment : *****')
    print(ack)
    # send acknowledgment
    msg, msg_bytes_ack = ack.build_message()
    sock.sendto(msg_bytes_ack, (addr[0], addr[1]))

    time.sleep(2)
    #build response
    # fail : no opt CoAPOptionContentFormat(3)
    coap_response = CoAP(type='con', mid=coap_message['mid'], code=2.05, pl='test payload server', opt=CoAPOptionList([CoAPOptionUriPath ("test option server"),CoAPOptionContentFormat(3)]))
    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    sock.sendto(msg_bytes, (addr[0], addr[1]))

    # receive acknowledgment
    msg_ack_recv, addr = sock.recvfrom(1024)
    # translate acknowledgment
    binary_msg_ack = Message(msg_ack_recv, CoAP)
    coap_ack_recv = binary_msg_ack.get_value()
    print('***** SERVER acknowledgment receive : *****')
    print(coap_ack_recv)

    sock.close()

def td_coap_core_10_PASS_client_emulator():
    default_PASS_client_emulator('con', 'get', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath("test_option_client"), CoAPOptionContentFormat(3)]))

def td_coap_core_10_FAIL_TOK_0_BYTE_client_emulator():
    default_PASS_client_emulator('con', 'get', 9, b'', 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath("test_option_client"), CoAPOptionContentFormat(3)]))

def td_coap_core_10_FAIL_TOK_9_BYTE_client_emulator():
    default_PASS_client_emulator('con', 'get', 9, b'0123456879', 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath("test_option_client"), CoAPOptionContentFormat(3)]))

def td_coap_core_10_PASS_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    # print(addr[0])
    # print(addr[1])
    # print(coap_message['mid'])
    #build response
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05, pl='test payload server', opt= CoAPOptionList([CoAPOptionUriPath ("test_option_server"),CoAPOptionContentFormat(3)] ))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_10_FAIL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv, addr = connexion.recvfrom(1024)
    #translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)
    # print(addr[0])
    # print(addr[1])
    # print(coap_message['mid'])
    #build response
    #fail : no opt CoAPOptionContentFormat(3)
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05, pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionUriPath("test_option_server")]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def main(argv):
    # Add argument with argparse to choose the interface
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--choice", choices=["ack", "noack"],
                        help="Choose if the application send acknowledgment or not")
    args = parser.parse_args()
    if args.choice == "ack":
        print("good choice")
    elif args.choice == "noack":
        print("good choice")
    else:
        # either amqp (amqp interface) or http (webserver)
        print("***********Server and Client mode with thread***********")
        _launch_sniffer('tmp/TD_COAP_CORE_10_fail.pcap')
        time.sleep(2)
        # td_coap_core_01_PASS_server_emulator()
        t1 = threading.Thread(target=td_coap_core_10_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_10_FAIL_TOK_0_BYTE_client_emulator)

        print("starting threads")
        t1.start()
        t2.start()

        print("waiting to join")
        t1.join()
        t2.join()
        time.sleep(2)
        _stop_sniffer()

        """
        #test case 1
        t1 = threading.Thread(target=td_coap_core_01_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_01_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_01_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_01_PASS_client_emulator)
        
        #test case 2
        t1 = threading.Thread(target=td_coap_core_02_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_02_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_02_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_02_PASS_client_emulator)
        
        #test case 3
        t1 = threading.Thread(target=td_coap_core_03_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_03_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_03_PASS_NO_PL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_03_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_03_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_03_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_03_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_03_FAIL_client_emulator)
        
        #test case 4
        t1 = threading.Thread(target=td_coap_core_04_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_04_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_04_PASS_NO_PL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_04_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_04_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_04_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_04_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_04_FAIL_client_emulator)
        
        #test case 5
        t1 = threading.Thread(target=td_coap_core_05_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_05_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_05_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_05_PASS_client_emulator)
        
        #test case 6
        t1 = threading.Thread(target=td_coap_core_06_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_06_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_06_PASS_NO_PL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_06_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_06_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_06_PASS_client_emulator)
        
        #test case 7
        t1 = threading.Thread(target=td_coap_core_07_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_07_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_07_PASS_NO_PL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_07_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_07_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_07_PASS_client_emulator)
        
        #give none
        t1 = threading.Thread(target=td_coap_core_07_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_07_FAIL_NO_PL_client_emulator)
        
        #give none
        t1 = threading.Thread(target=td_coap_core_07_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_07_FAIL_NO_OPT_client_emulator)
        
        #test case 8
        t1 = threading.Thread(target=td_coap_core_08_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_08_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_08_PASS_NO_PL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_08_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_08_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_08_PASS_client_emulator)
        
        #give none
        t1 = threading.Thread(target=td_coap_core_08_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_08_FAIL_NO_PL_client_emulator)
        
        #give none
        t1 = threading.Thread(target=td_coap_core_08_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_08_FAIL_NO_OPT_client_emulator)
        
        #test case 9
        t1 = threading.Thread(target=td_coap_core_09_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_09_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_09_FAIL_NO_OPT_server_emulator)
        t2 = threading.Thread(target=td_coap_core_09_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_09_FAIL_NO_TOK_server_emulator)
        t2 = threading.Thread(target=td_coap_core_09_PASS_client_emulator)

        t1 = threading.Thread(target=td_coap_core_09_FAIL_NO_PL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_09_PASS_client_emulator)
        
        #test case 10
        t1 = threading.Thread(target=td_coap_core_10_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_10_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_10_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_10_FAIL_TOK_0_BYTE_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_10_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_10_FAIL_TOK_9_BYTE_client_emulator)

        t1 = threading.Thread(target=td_coap_core_10_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_10_PASS_client_emulator)
        
        
        
        
        
        """


if __name__ == "__main__":

    main(sys.argv[1:])

