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

# def server_emulator():
#     # waiting for receive a message CoAP/UDP/IPv4
#     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     sock.bind((IP, UDP_PORT))
#     msg_recv, addr = sock.recvfrom(1024)
#     #translate message
#     binary_msg = Message(msg_recv, CoAP)
#     coap_message = binary_msg.get_value()
#     return coap_message, addr


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


def td_coap_core_11_PASS_client_emulator():
    coap_msg = CoAP(type='con', code='get', mid=9, tok=1, pl='test payload client',
                    opt=CoAPOptionList([CoAPOptionUriPath("test option client"), CoAPOptionContentFormat(3)]))
    print('***** CLIENT What we send : *****')
    print(coap_msg)
    msg, msg_bytes = coap_msg.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes, (IP, UDP_PORT))

    # receive acknowledgment
    ack_recev = sock.recv(1024)
    # translate acknowledgment
    binary_msg_ack = Message(ack_recev, CoAP)
    coap_ack_recv = binary_msg_ack.get_value()
    print('***** CLIENT acknowledgment receive : *****')
    print(coap_ack_recv)

    # receive message
    reply = sock.recv(1024)
    # translate message
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

def td_coap_core_11_FAIL_TOK_0_BYTE_client_emulator():
    coap_msg = CoAP(type='con', code='get', mid=9, tok=b'', pl='test payload client',
                    opt=CoAPOptionList([CoAPOptionUriPath("test option client"), CoAPOptionContentFormat(3)]))
    print('***** CLIENT What we send : *****')
    print(coap_msg)
    msg, msg_bytes = coap_msg.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes, (IP, UDP_PORT))

    # receive acknowledgment
    ack_recev = sock.recv(1024)
    # translate acknowledgment
    binary_msg_ack = Message(ack_recev, CoAP)
    coap_ack_recv = binary_msg_ack.get_value()
    print('***** CLIENT acknowledgment receive : *****')
    print(coap_ack_recv)

    # receive message
    reply = sock.recv(1024)
    # translate message
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

def td_coap_core_11_FAIL_TOK_9_BYTE_client_emulator():
    coap_msg = CoAP(type='con', code='get', mid=9, tok=b'0123456879', pl='test payload client',
                    opt=CoAPOptionList([CoAPOptionUriPath("test option client"), CoAPOptionContentFormat(3)]))
    print('***** CLIENT What we send : *****')
    print(coap_msg)
    msg, msg_bytes = coap_msg.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes, (IP, UDP_PORT))

    # receive acknowledgment
    ack_recev = sock.recv(1024)
    # translate acknowledgment
    binary_msg_ack = Message(ack_recev, CoAP)
    coap_ack_recv = binary_msg_ack.get_value()
    print('***** CLIENT acknowledgment receive : *****')
    print(coap_ack_recv)

    # receive message
    reply = sock.recv(1024)
    # translate message
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

def td_coap_core_11_PASS_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, UDP_PORT))
    msg_recv, addr = sock.recvfrom(1024)
    # translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)

    # build ack
    ack = CoAP(type='ack', mid=coap_message['mid'], code=0)
    print('***** SERVER send acknowledgment : *****')
    print(ack)
    # send acknowledgment
    msg, msg_bytes_ack = ack.build_message()
    sock.sendto(msg_bytes_ack, (addr[0], addr[1]))

    time.sleep(2)
    # build response
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05,
                         pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionUriPath("test option server"), CoAPOptionContentFormat(3)]))
    print('***** SERVER What we send : *****')
    print(coap_response)
    # send response
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

def td_coap_core_11_FAIL_NO_TOK_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, UDP_PORT))
    msg_recv, addr = sock.recvfrom(1024)
    # translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)

    # build ack
    ack = CoAP(type='ack', mid=coap_message['mid'], code=0)
    print('***** SERVER send acknowledgment : *****')
    print(ack)
    # send acknowledgment
    msg, msg_bytes_ack = ack.build_message()
    sock.sendto(msg_bytes_ack, (addr[0], addr[1]))

    time.sleep(2)
    # build response
    coap_response = CoAP(type='con', mid=coap_message['mid'], code=2.05,
                         pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionUriPath("test option server"), CoAPOptionContentFormat(3)]))
    print('***** SERVER What we send : *****')
    print(coap_response)
    # send response
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


def td_coap_core_11_FAIL_NO_PL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, UDP_PORT))
    msg_recv, addr = sock.recvfrom(1024)
    # translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)

    # build ack
    ack = CoAP(type='ack', mid=coap_message['mid'], code=0)
    print('***** SERVER send acknowledgment : *****')
    print(ack)
    # send acknowledgment
    msg, msg_bytes_ack = ack.build_message()
    sock.sendto(msg_bytes_ack, (addr[0], addr[1]))

    time.sleep(2)
    # build response
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05,
                         opt=CoAPOptionList([CoAPOptionUriPath("test option server"), CoAPOptionContentFormat(3)]))
    print('***** SERVER What we send : *****')
    print(coap_response)
    # send response
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

def td_coap_core_12_PASS_client_emulator():
    default_PASS_client_emulator('con', 'get', 9, b'', 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath("test_option_client"), CoAPOptionContentFormat(3)]))

def td_coap_core_12_PASS_server_emulator():
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

def td_coap_core_12_FAIL_server_emulator():
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
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=1, code=2.05, pl='test payload server', opt= CoAPOptionList([CoAPOptionUriPath ("test_option_server"),CoAPOptionContentFormat(3)] ))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_13_PASS_client_emulator():
    default_PASS_client_emulator('con', 'get', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath("seg1"),CoAPOptionUriPath("seg2"), CoAPOptionUriPath("seg3"), CoAPOptionContentFormat(3)]))

def td_coap_core_13_FAIL_client_emulator():
    default_PASS_client_emulator('con', 'get', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath("/seg1"),CoAPOptionUriPath("/seg2"), CoAPOptionUriPath("/seg3"), CoAPOptionContentFormat(3)]))

def td_coap_core_13_PASS_server_emulator():
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

def td_coap_core_14_PASS_client_emulator():
    default_PASS_client_emulator('con', 'get', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriQuery("first=1"),CoAPOptionUriQuery("second=2"), CoAPOptionContentFormat(3)]))

def td_coap_core_14_FAIL_client_emulator():
    default_PASS_client_emulator('con', 'get', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriQuery("first=1"), CoAPOptionContentFormat(3)]))


def td_coap_core_14_PASS_server_emulator():
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
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05, pl='test payload server', opt= CoAPOptionList([CoAPOptionUriPath ("test_option_server"),CoAPOptionContentFormat(3)]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_14_FAIL_server_emulator():
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
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05, pl='test payload server', opt= CoAPOptionList([CoAPOptionUriPath ("test_option_server")] ))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_17_PASS_client_emulator():
    default_PASS_client_emulator('non', 'get', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath ("test_option_client"), CoAPOptionContentFormat(3)]))

def td_coap_core_17_PASS_server_emulator():
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
    coap_response = CoAP(type='non', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05, pl='test payload server', opt= CoAPOptionList([CoAPOptionUriPath ("test_option_server"),CoAPOptionContentFormat(3)]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_17_FAIL_server_emulator():
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
    coap_response = CoAP(type='non', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05, pl='test payload server', opt= CoAPOptionList([CoAPOptionUriPath ("test_option_server")]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    time.sleep(2)
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_17_FAIL_ACK_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, UDP_PORT))
    msg_recv, addr = sock.recvfrom(1024)
    # translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)

    # build ack
    ack = CoAP(type='ack', mid=coap_message['mid'], code=0)
    print('***** SERVER send acknowledgment : *****')
    print(ack)
    # send acknowledgment
    msg, msg_bytes_ack = ack.build_message()
    sock.sendto(msg_bytes_ack, (addr[0], addr[1]))

    time.sleep(2)
    # build response
    coap_response = CoAP(type='non', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05, pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionUriPath("test option server"), CoAPOptionContentFormat(3)]))
    print('***** SERVER What we send : *****')
    print(coap_response)
    # send response
    msg, msg_bytes = coap_response.build_message()
    sock.sendto(msg_bytes, (addr[0], addr[1]))
    sock.close()

def td_coap_core_18_PASS_client_emulator():
    default_PASS_client_emulator('con', 'post', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath ("test_option_client"), CoAPOptionContentFormat(3)]))

def td_coap_core_18_PASS_server_emulator():
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
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.01, pl='test payload server', opt= CoAPOptionList([CoAPOptionLocationPath ("location1"),CoAPOptionLocationPath ("location2"),CoAPOptionLocationPath ("location3"),CoAPOptionContentFormat(3)]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_18_FAIL_2_location_server_emulator():
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
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.01, pl='test payload server', opt= CoAPOptionList([CoAPOptionLocationPath ("location1"),CoAPOptionLocationPath ("location2"),CoAPOptionContentFormat(3)]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_18_FAIL_server_emulator():
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
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.01, pl='test payload server', opt= CoAPOptionList([CoAPOptionLocationPath (".."),CoAPOptionLocationPath ("/location2"), CoAPOptionLocationPath ("/location3"), CoAPOptionContentFormat(3)]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_19_PASS_client_emulator():
    default_PASS_client_emulator('con', 'post', 9, 1, 'test payload client',
                                 CoAPOptionList([CoAPOptionUriPath ("test_option_client"), CoAPOptionContentFormat(3)]))

def td_coap_core_19_PASS_server_emulator():
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
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.01, pl='test payload server', opt= CoAPOptionList([CoAPOptionLocationQuery("first=1"),CoAPOptionLocationQuery("second=2"),CoAPOptionContentFormat(3)]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_19_PASS_NO_PL_server_emulator():
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
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.01, opt= CoAPOptionList([CoAPOptionLocationQuery("first=1"),CoAPOptionLocationQuery("second=2")]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_19_FAIL_server_emulator():
    #no coapoptionformt with payload
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
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.01, pl='test payload server', opt= CoAPOptionList([CoAPOptionLocationQuery("first=1"),CoAPOptionLocationQuery("second=2")]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_19_FAIL_WRONG_OPT_server_emulator():
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
    coap_response = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.01, pl='test payload server', opt= CoAPOptionList([CoAPOptionLocationQuery("?=."),CoAPOptionLocationQuery("&=.."),CoAPOptionContentFormat(3)]))

    print('***** SERVER What we send : *****')
    print(coap_response)
    #send response
    msg, msg_bytes = coap_response.build_message()
    connexion.sendto(msg_bytes, (addr[0], addr[1]))
    connexion.close()

def td_coap_core_20_PASS_client_emulator():
    coap_msg = CoAP(type='con', code='get', mid=9, tok=b'01',
                    opt=CoAPOptionList([CoAPOptionAccept(0)]))
    print('***** CLIENT What we send : *****')
    print(coap_msg)
    msg, msg_bytes = coap_msg.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes, (IP, UDP_PORT))

    # receive message1
    ack_recev = sock.recv(1024)
    # translate message1
    binary_msg_ack = Message(ack_recev, CoAP)
    coap_ack_recv = binary_msg_ack.get_value()
    print('***** CLIENT acknowledgment receive : *****')
    print(coap_ack_recv)

    # build response
    ack = CoAP(type='con', mid=8, tok=2, code='get', opt=CoAPOptionList([CoAPOptionAccept(41)]))
    print('***** CLIENT send acknowledgment : *****')
    print(ack)
    # send response
    msg, msg_bytes_ack = ack.build_message()
    sock.sendto(msg_bytes_ack, (IP, UDP_PORT))

    # receive message2
    reply = sock.recv(1024)
    # translate message2
    binary_msg = Message(reply, CoAP)
    coap_message = binary_msg.get_value()
    print('***** CLIENT What we receive : *****')
    print(coap_message)

    sock.close()

    return reply

def td_coap_core_20_FAIL_client_emulator():
    coap_msg = CoAP(type='con', code='get', mid=9, tok=b'01',
                    opt=CoAPOptionList([CoAPOptionAccept(0)]))
    print('***** CLIENT What we send : *****')
    print(coap_msg)
    msg, msg_bytes = coap_msg.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes, (IP, UDP_PORT))

    # receive message1
    ack_recev = sock.recv(1024)
    # translate message1
    binary_msg_ack = Message(ack_recev, CoAP)
    coap_ack_recv = binary_msg_ack.get_value()
    print('***** CLIENT acknowledgment receive : *****')
    print(coap_ack_recv)

    # build response
    ack = CoAP(type='con', mid=coap_ack_recv['mid'], tok=coap_ack_recv['tok'], code='get', opt=CoAPOptionList([CoAPOptionAccept(41)]))
    print('***** CLIENT send acknowledgment : *****')
    print(ack)
    # send response
    msg, msg_bytes_ack = ack.build_message()
    sock.sendto(msg_bytes_ack, (IP, UDP_PORT))

    # receive message2
    reply = sock.recv(1024)
    # translate message2
    binary_msg = Message(reply, CoAP)
    coap_message = binary_msg.get_value()
    print('***** CLIENT What we receive : *****')
    print(coap_message)

    sock.close()

    return reply

def td_coap_core_20_PASS_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, UDP_PORT))
    msg_recv, addr = sock.recvfrom(1024)
    # translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)

    # build response1
    coap_response1 = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05,
                         pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionAccept(0), CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send : *****')
    print(coap_response1)
    # send response
    msg, msg_bytes1 = coap_response1.build_message()
    sock.sendto(msg_bytes1, (addr[0], addr[1]))

    # receive response
    msg_ack_recv, addr = sock.recvfrom(1024)
    # translate response
    binary_msg_ack = Message(msg_ack_recv, CoAP)
    coap_ack_recv = binary_msg_ack.get_value()
    print('***** SERVER acknowledgment receive : *****')
    print(coap_ack_recv)

    # build response
    coap_response2 = CoAP(type='con', mid=coap_ack_recv['mid'], tok=coap_ack_recv['tok'], code=2.05,
                         pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionAccept(41), CoAPOptionContentFormat(41)]))
    print('***** SERVER What we send : *****')
    print(coap_response2)
    # send response
    msg, msg_bytes2 = coap_response2.build_message()
    sock.sendto(msg_bytes2, (addr[0], addr[1]))
    sock.close()

def td_coap_core_20_FAIL_WRONG_FORMAT_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, UDP_PORT))
    msg_recv, addr = sock.recvfrom(1024)
    # translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive : *****')
    print(coap_message)

    # build response1
    coap_response1 = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05,
                         pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionAccept(0), CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send : *****')
    print(coap_response1)
    # send response
    msg, msg_bytes1 = coap_response1.build_message()
    sock.sendto(msg_bytes1, (addr[0], addr[1]))

    # receive response
    msg_ack_recv, addr = sock.recvfrom(1024)
    # translate response
    binary_msg_ack = Message(msg_ack_recv, CoAP)
    coap_ack_recv = binary_msg_ack.get_value()
    print('***** SERVER acknowledgment receive : *****')
    print(coap_ack_recv)

    # build response
    coap_response2 = CoAP(type='con', mid=coap_ack_recv['mid'], tok=coap_ack_recv['tok'], code=2.05,
                         pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionAccept(41), CoAPOptionContentFormat(4)]))
    print('***** SERVER What we send : *****')
    print(coap_response2)
    # send response
    msg, msg_bytes2 = coap_response2.build_message()
    sock.sendto(msg_bytes2, (addr[0], addr[1]))
    sock.close()

def td_coap_core_21_PASS_client_emulator():
    coap_msg = CoAP(type='con', code='get', mid=9, tok=b'01', opt=CoAPOptionList([ CoAPOptionUriPath(val='validate')]))
    print('***** CLIENT What we send 1 : *****')
    print(coap_msg)
    msg, msg_bytes = coap_msg.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes, (IP, UDP_PORT))

    # receive message1
    ack_recev = sock.recv(1024)
    # translate message1
    binary_msg_ack = Message(ack_recev, CoAP)
    coap_ack_recv = binary_msg_ack.get_value()
    print('***** CLIENT What we receive 1 : *****')
    print(coap_ack_recv)

    # build response
    ack = CoAP(type='con', code='get', mid=10, tok=b'02',  opt=coap_ack_recv['opt'])
    print('***** CLIENT What we send 2 : *****')
    print(ack)
    # send response
    msg, msg_bytes_ack = ack.build_message()
    sock.sendto(msg_bytes_ack, (IP, UDP_PORT))

    # receive message2
    reply = sock.recv(1024)
    # translate message2
    binary_msg = Message(reply, CoAP)
    coap_message = binary_msg.get_value()
    print('***** CLIENT What we receive 2 : *****')
    print(coap_message)

    # build response
    ack3 = CoAP(type='con', code='put')
    print('***** CLIENT What we send 3 : *****')
    print(ack3)
    # send response
    msg, msg_bytes_ack3 = ack3.build_message()
    sock.sendto(msg_bytes_ack3, (IP, UDP_PORT))

    # receive message
    reply3 = sock.recv(1024)
    # translate message2
    binary_msg3 = Message(reply3, CoAP)
    coap_message3 = binary_msg3.get_value()
    print('***** CLIENT What we receive 3 : *****')
    print(coap_message3)

     # build response
    ack4 = CoAP(type='con', code='get', mid=11, tok=b'03', opt=coap_message['opt'])
    print('***** CLIENT What we send 4 : *****')
    print(ack4)
    # send response
    msg, msg_bytes_ack4 = ack4.build_message()
    sock.sendto(msg_bytes_ack4, (IP, UDP_PORT))

    # receive message2
    reply4 = sock.recv(1024)
    # translate message2
    binary_msg4 = Message(reply4, CoAP)
    coap_message4 = binary_msg4.get_value()
    print('***** CLIENT What we receive 4 : *****')
    print(coap_message4)

    sock.close()

    return reply

def td_coap_core_21_FAIL_client_emulator():
    coap_msg = CoAP(type='con', code='get', mid=9, tok=b'02', opt=CoAPOptionList([ CoAPOptionUriPath(val='validate')]))
    print('***** CLIENT What we send 1 : *****')
    print(coap_msg)
    msg, msg_bytes = coap_msg.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes, (IP, UDP_PORT))

    # receive message1
    ack_recev = sock.recv(1024)
    # translate message1
    binary_msg_ack = Message(ack_recev, CoAP)
    coap_ack_recv = binary_msg_ack.get_value()
    print('***** CLIENT What we receive 1 : *****')
    print(coap_ack_recv)

    # build response
    ack = CoAP(type='con', code='get', mid=coap_ack_recv['mid'], tok=coap_ack_recv['tok'],  opt=coap_ack_recv['opt'])
    print('***** CLIENT What we send 2 : *****')
    print(ack)
    # send response
    msg, msg_bytes_ack = ack.build_message()
    sock.sendto(msg_bytes_ack, (IP, UDP_PORT))

    # receive message2
    reply = sock.recv(1024)
    # translate message2
    binary_msg = Message(reply, CoAP)
    coap_message = binary_msg.get_value()
    print('***** CLIENT What we receive 2 : *****')
    print(coap_message)

    # build response
    ack3 = CoAP(type='con', code='put')
    print('***** CLIENT What we send 3 : *****')
    print(ack3)
    # send response
    msg, msg_bytes_ack3 = ack3.build_message()
    sock.sendto(msg_bytes_ack3, (IP, UDP_PORT))

    # receive message
    reply3 = sock.recv(1024)
    # translate message2
    binary_msg3 = Message(reply3, CoAP)
    coap_message3 = binary_msg3.get_value()
    print('***** CLIENT What we receive 3 : *****')
    print(coap_message3)

     # build response
    ack4 = CoAP(type='con', code='get', mid=coap_ack_recv['mid'], tok=coap_ack_recv['tok'], opt=coap_message['opt'])
    print('***** CLIENT What we send 4 : *****')
    print(ack4)
    # send response
    msg, msg_bytes_ack4 = ack4.build_message()
    sock.sendto(msg_bytes_ack4, (IP, UDP_PORT))

    # receive message2
    reply4 = sock.recv(1024)
    # translate message2
    binary_msg4 = Message(reply4, CoAP)
    coap_message4 = binary_msg4.get_value()
    print('***** CLIENT What we receive 4 : *****')
    print(coap_message4)

    sock.close()

    return reply

def td_coap_core_21_PASS_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, UDP_PORT))
    msg_recv, addr1 = sock.recvfrom(1024)
    # translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive 1 : *****')
    print(coap_message)

    # build response1
    coap_response1 = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05,
                         pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionETag(1), CoAPOptionUriPath(val='validate'), CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send 1 : *****')
    print(coap_response1)
    # send response
    msg, msg_bytes1 = coap_response1.build_message()
    sock.sendto(msg_bytes1, (addr1[0], addr1[1]))

    # receive response
    msg_ack_recv, addr2 = sock.recvfrom(1024)
    # translate response
    binary_msg_ack = Message(msg_ack_recv, CoAP)
    coap_ack_recv = binary_msg_ack.get_value()
    print('***** SERVER What we receive 2 : *****')
    print(coap_ack_recv)

    # build response
    coap_response2 = CoAP(type='con', mid=coap_ack_recv['mid'], tok=coap_ack_recv['tok'], code=2.03,
                         opt=coap_ack_recv['opt'])
    print('***** SERVER What we send 2 : *****')
    print(coap_response2)
    # send response
    msg, msg_bytes2 = coap_response2.build_message()
    sock.sendto(msg_bytes2, (addr2[0], addr2[1]))

    # receive response
    msg_ack_recv3, addr3 = sock.recvfrom(1024)
    # translate response
    binary_msg_ack3 = Message(msg_ack_recv3, CoAP)
    coap_ack_recv3 = binary_msg_ack3.get_value()
    print('***** SERVER What we receive 3 : *****')
    print(coap_ack_recv3)

    # build response
    coap_response3 = CoAP(type='con', mid=coap_ack_recv3['mid'], tok=coap_ack_recv3['tok'], code=2.04,
                          opt=coap_ack_recv3['opt'])
    print('***** SERVER What we send 3 : *****')
    print(coap_response3)
    # send response
    msg, msg_bytes3 = coap_response3.build_message()
    sock.sendto(msg_bytes3, (addr3[0], addr3[1]))

    # receive response
    msg_ack_recv4, addr4 = sock.recvfrom(1024)
    # translate response
    binary_msg_ack4 = Message(msg_ack_recv4, CoAP)
    coap_ack_recv4 = binary_msg_ack4.get_value()
    print('***** SERVER What we receive 4 : *****')
    print(coap_ack_recv4)

    # build response
    coap_response4 = CoAP(type='con', mid=coap_ack_recv4['mid'], tok=coap_ack_recv4['tok'], code=2.05, pl='test payload server3',
                          opt=CoAPOptionList([CoAPOptionETag(3), CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send 4 : *****')
    print(coap_response4)
    # send response
    msg, msg_bytes4 = coap_response4.build_message()
    sock.sendto(msg_bytes4, (addr4[0], addr4[1]))
    sock.close()

def td_coap_core_21_FAIL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, UDP_PORT))
    msg_recv, addr1 = sock.recvfrom(1024)
    # translate message
    binary_msg = Message(msg_recv, CoAP)
    coap_message = binary_msg.get_value()
    print('***** SERVER What we receive 1 : *****')
    print(coap_message)

    # build response1
    coap_response1 = CoAP(type='con', mid=coap_message['mid'], tok=coap_message['tok'], code=2.05,
                         pl='test payload server',
                         opt=CoAPOptionList([CoAPOptionETag(1), CoAPOptionUriPath(val='validate'), CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send 1 : *****')
    print(coap_response1)
    # send response
    msg, msg_bytes1 = coap_response1.build_message()
    sock.sendto(msg_bytes1, (addr1[0], addr1[1]))

    # receive response
    msg_ack_recv, addr2 = sock.recvfrom(1024)
    # translate response
    binary_msg_ack = Message(msg_ack_recv, CoAP)
    coap_ack_recv = binary_msg_ack.get_value()
    print('***** SERVER What we receive 2 : *****')
    print(coap_ack_recv)

    # build response
    coap_response2 = CoAP(type='con', mid=coap_ack_recv['mid'], tok=coap_ack_recv['tok'], code=2.03,
                         opt=coap_ack_recv['opt'])
    print('***** SERVER What we send 2 : *****')
    print(coap_response2)
    # send response
    msg, msg_bytes2 = coap_response2.build_message()
    sock.sendto(msg_bytes2, (addr2[0], addr2[1]))

    # receive response
    msg_ack_recv3, addr3 = sock.recvfrom(1024)
    # translate response
    binary_msg_ack3 = Message(msg_ack_recv3, CoAP)
    coap_ack_recv3 = binary_msg_ack3.get_value()
    print('***** SERVER What we receive 3 : *****')
    print(coap_ack_recv3)

    # build response
    coap_response3 = CoAP(type='con', mid=coap_ack_recv3['mid'], tok=coap_ack_recv3['tok'], code=2.04,
                          opt=coap_ack_recv3['opt'])
    print('***** SERVER What we send 3 : *****')
    print(coap_response3)
    # send response
    msg, msg_bytes3 = coap_response3.build_message()
    sock.sendto(msg_bytes3, (addr3[0], addr3[1]))

    # receive response
    msg_ack_recv4, addr4 = sock.recvfrom(1024)
    # translate response
    binary_msg_ack4 = Message(msg_ack_recv4, CoAP)
    coap_ack_recv4 = binary_msg_ack4.get_value()
    print('***** SERVER What we receive 4 : *****')
    print(coap_ack_recv4)

    # build response
    coap_response4 = CoAP(type='con', mid=coap_ack_recv4['mid'], tok=coap_ack_recv4['tok'], code=2.05, pl='test payload server',
                          opt=CoAPOptionList([CoAPOptionETag(3), CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send 4 : *****')
    print(coap_response4)
    # send response
    msg, msg_bytes4 = coap_response4.build_message()
    sock.sendto(msg_bytes4, (addr4[0], addr4[1]))
    sock.close()

def td_coap_core_22_PASS_client_emulator():
    coap_msg1 = CoAP(type='con', code='get', mid=9, tok=b'02', opt=CoAPOptionList([ CoAPOptionUriPath(val='validate')]))
    print('***** CLIENT What we send 1 : *****')
    print(coap_msg1)
    msg, msg_bytes1 = coap_msg1.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.sendto(msg_bytes1, (IP,UDP_PORT))
    #receive message
    reply1 = sock.recv(1024)
    #translate message
    binary_msg1 = Message(reply1, CoAP)
    coap_message1 = binary_msg1.get_value()
    print('***** CLIENT What we receive 1 : *****')
    print(coap_message1)

    ETAG1=coap_message1['opt']
    coap_msg2 = CoAP(type='con', code='put', mid=10, tok=b'03',pl='test payload client2',
                          opt=CoAPOptionList(
                              [ CoAPOptionIfMatch(ETAG1[0]['val']), CoAPOptionUriPath(val='validate'), CoAPOptionContentFormat(0)]))

    print('***** CLIENT What we send 2 : *****')
    print(coap_msg1)
    msg, msg_bytes2 = coap_msg2.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes2, (IP, UDP_PORT))
    # receive message
    reply2 = sock.recv(1024)
    # translate message
    binary_msg2 = Message(reply2, CoAP)
    coap_message2 = binary_msg2.get_value()
    print('***** CLIENT What we receive 2 : *****')
    print(coap_message2)

    coap_msg3 = CoAP(type='con', code='get', mid=11, tok=b'04', pl='test payload client2',
                     opt=CoAPOptionList(
                         [CoAPOptionUriPath(val='validate'),CoAPOptionContentFormat(0)]))

    print('***** CLIENT What we send 3 : *****')
    print(coap_msg3)
    msg, msg_bytes3 = coap_msg3.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes3, (IP, UDP_PORT))
    # receive message
    reply3 = sock.recv(1024)
    # translate message
    binary_msg3 = Message(reply3, CoAP)
    coap_message3 = binary_msg3.get_value()
    print('***** CLIENT What we receive 3 : *****')
    print(coap_message3)

    coap_msg4 = CoAP(type='con', code='put', pl='test payload client4',
                     opt=CoAPOptionList([CoAPOptionUriPath(val='validate'),CoAPOptionContentFormat(0)]))

    print('***** CLIENT What we send 4 : *****')
    print(coap_msg4)
    msg, msg_bytes4 = coap_msg4.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes4, (IP, UDP_PORT))
    # receive message
    reply4 = sock.recv(1024)
    # translate message
    binary_msg4 = Message(reply4, CoAP)
    coap_message4 = binary_msg4.get_value()
    print('***** CLIENT What we receive 4 : *****')
    print(coap_message4)

    ETAG2 = coap_message3['opt']
    coap_msg5 = CoAP(type='con', code='put', mid=12, tok=b'05',pl='test payload client5',
                          opt=CoAPOptionList(
                              [ CoAPOptionIfMatch(ETAG2[0]['val']), CoAPOptionUriPath(val='validate'), CoAPOptionContentFormat(0)]))
    print('***** CLIENT What we send 5 : *****')
    print(coap_msg5)
    msg, msg_bytes5 = coap_msg5.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes5, (IP, UDP_PORT))
    # receive message
    reply5 = sock.recv(1024)
    # translate message
    binary_msg5 = Message(reply5, CoAP)
    coap_message5 = binary_msg5.get_value()
    print('***** CLIENT What we receive 5 : *****')
    print(coap_message5)

    sock.close()

def td_coap_core_22_FAIL_client_emulator():
    coap_msg1 = CoAP(type='con', code='get', mid=9, tok=b'02', opt=CoAPOptionList([ CoAPOptionUriPath(val='validate')]))
    print('***** CLIENT What we send 1 : *****')
    print(coap_msg1)
    msg, msg_bytes1 = coap_msg1.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.sendto(msg_bytes1, (IP,UDP_PORT))
    #receive message
    reply1 = sock.recv(1024)
    #translate message
    binary_msg1 = Message(reply1, CoAP)
    coap_message1 = binary_msg1.get_value()
    print('***** CLIENT What we receive 1 : *****')
    print(coap_message1)

    ETAG1=coap_message1['opt']
    coap_msg2 = CoAP(type='con', code='put', mid=9, tok=b'02',pl='test payload client2',
                          opt=CoAPOptionList(
                              [ CoAPOptionIfMatch(ETAG1[0]['val']), CoAPOptionUriPath(val='validate'), CoAPOptionContentFormat(0)]))

    print('***** CLIENT What we send 2 : *****')
    print(coap_msg1)
    msg, msg_bytes2 = coap_msg2.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes2, (IP, UDP_PORT))
    # receive message
    reply2 = sock.recv(1024)
    # translate message
    binary_msg2 = Message(reply2, CoAP)
    coap_message2 = binary_msg2.get_value()
    print('***** CLIENT What we receive 2 : *****')
    print(coap_message2)

    coap_msg3 = CoAP(type='con', code='get', mid=9, tok=b'02', pl='test payload client2',
                     opt=CoAPOptionList(
                         [CoAPOptionUriPath(val='validate'),CoAPOptionContentFormat(0)]))

    print('***** CLIENT What we send 3 : *****')
    print(coap_msg3)
    msg, msg_bytes3 = coap_msg3.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes3, (IP, UDP_PORT))
    # receive message
    reply3 = sock.recv(1024)
    # translate message
    binary_msg3 = Message(reply3, CoAP)
    coap_message3 = binary_msg3.get_value()
    print('***** CLIENT What we receive 3 : *****')
    print(coap_message3)

    coap_msg4 = CoAP(type='con', code='put', pl='test payload client4',
                     opt=CoAPOptionList([CoAPOptionUriPath(val='validate'),CoAPOptionContentFormat(0)]))

    print('***** CLIENT What we send 4 : *****')
    print(coap_msg4)
    msg, msg_bytes4 = coap_msg4.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes4, (IP, UDP_PORT))
    # receive message
    reply4 = sock.recv(1024)
    # translate message
    binary_msg4 = Message(reply4, CoAP)
    coap_message4 = binary_msg4.get_value()
    print('***** CLIENT What we receive 4 : *****')
    print(coap_message4)

    ETAG2 = coap_message3['opt']
    coap_msg5 = CoAP(type='con', code='put', mid=9, tok=b'02',pl='test payload client5',
                          opt=CoAPOptionList(
                              [ CoAPOptionIfMatch(ETAG2[0]['val']), CoAPOptionUriPath(val='validate'), CoAPOptionContentFormat(0)]))
    print('***** CLIENT What we send 5 : *****')
    print(coap_msg5)
    msg, msg_bytes5 = coap_msg5.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes5, (IP, UDP_PORT))
    # receive message
    reply5 = sock.recv(1024)
    # translate message
    binary_msg5 = Message(reply5, CoAP)
    coap_message5 = binary_msg5.get_value()
    print('***** CLIENT What we receive 5 : *****')
    print(coap_message5)

    sock.close()

def td_coap_core_22_PASS_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv1, addr1 = connexion.recvfrom(1024)
    #translate message
    binary_msg1 = Message(msg_recv1, CoAP)
    coap_message1 = binary_msg1.get_value()
    print('***** SERVER What we receive 1 : *****')
    print(coap_message1)
    #build response
    coap_response1 = CoAP(type='con', mid=coap_message1['mid'], tok=coap_message1['tok'], code=2.05,
                          pl='test payload server',
                          opt=CoAPOptionList(
                              [CoAPOptionETag(1), CoAPOptionUriPath(val='validate'), CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send 1 : *****')
    print(coap_response1)
    #send response
    msg, msg_bytes1 = coap_response1.build_message()
    connexion.sendto(msg_bytes1, (addr1[0], addr1[1]))

    #receive response
    msg_recv2, addr2 = connexion.recvfrom(1024)
    # translate message
    binary_msg2 = Message(msg_recv2, CoAP)
    coap_message2 = binary_msg2.get_value()
    print('***** SERVER What we receive 2 : *****')
    print(coap_message2)
    # build response
    coap_response2 = CoAP(type='con', mid=coap_message2['mid'], tok=coap_message2['tok'], code=2.04,
                          pl='test payload server',
                          opt=CoAPOptionList([CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send 2 : *****')
    print(coap_response2)
    # send response
    msg, msg_bytes2 = coap_response2.build_message()
    connexion.sendto(msg_bytes2, (addr2[0], addr2[1]))

    # receive response
    msg_recv3, addr3 = connexion.recvfrom(1024)
    # translate message
    binary_msg3 = Message(msg_recv3, CoAP)
    coap_message3 = binary_msg3.get_value()
    print('***** SERVER What we receive 3 : *****')
    print(coap_message3)
    # build response
    coap_response3 = CoAP(type='con', mid=coap_message3['mid'], tok=coap_message3['tok'], code=2.05,
                          pl=coap_message2['pl'],
                          opt=CoAPOptionList([CoAPOptionETag(2), CoAPOptionUriPath(val='validate'), CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send 3 : *****')
    print(coap_response3)
    # send response
    msg, msg_bytes3 = coap_response3.build_message()
    connexion.sendto(msg_bytes3, (addr3[0], addr3[1]))

    # receive response
    msg_recv4, addr4 = connexion.recvfrom(1024)
    # translate message
    binary_msg4 = Message(msg_recv4, CoAP)
    coap_message4 = binary_msg4.get_value()
    print('***** SERVER What we receive 4 : *****')
    print(coap_message4)
    # build response
    coap_response4 = CoAP(type='con', mid=coap_message4['mid'], tok=coap_message4['tok'], code=2.04,
                          pl='test payload server3',
                          opt=CoAPOptionList(
                              [CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send 4 : *****')
    print(coap_response4)
    # send response
    msg, msg_bytes4 = coap_response4.build_message()
    connexion.sendto(msg_bytes4, (addr4[0], addr4[1]))

    # receive response
    msg_recv5, addr5 = connexion.recvfrom(1024)
    # translate message
    binary_msg5 = Message(msg_recv5, CoAP)
    coap_message5 = binary_msg5.get_value()
    print('***** SERVER What we receive 5 : *****')
    print(coap_message5)
    # build response
    coap_response5 = CoAP(type='con', mid=coap_message5['mid'], tok=coap_message5['tok'], code=4.12,
                          pl='test payload server3',
                          opt=CoAPOptionList([CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send 5 : *****')
    print(coap_response5)
    # send response
    msg, msg_bytes5 = coap_response5.build_message()
    connexion.sendto(msg_bytes5, (addr5[0], addr5[1]))

    connexion.close()

def td_coap_core_22_FAIL_server_emulator():
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv1, addr1 = connexion.recvfrom(1024)
    #translate message
    binary_msg1 = Message(msg_recv1, CoAP)
    coap_message1 = binary_msg1.get_value()
    print('***** SERVER What we receive 1 : *****')
    print(coap_message1)
    #build response
    coap_response1 = CoAP(type='con', mid=coap_message1['mid'], tok=coap_message1['tok'], code=2.05,
                          pl='test payload server',
                          opt=CoAPOptionList(
                              [CoAPOptionETag(1), CoAPOptionUriPath(val='validate'), CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send 1 : *****')
    print(coap_response1)
    #send response
    msg, msg_bytes1 = coap_response1.build_message()
    connexion.sendto(msg_bytes1, (addr1[0], addr1[1]))

    #receive response
    msg_recv2, addr2 = connexion.recvfrom(1024)
    # translate message
    binary_msg2 = Message(msg_recv2, CoAP)
    coap_message2 = binary_msg2.get_value()
    print('***** SERVER What we receive 2 : *****')
    print(coap_message2)
    # build response
    coap_response2 = CoAP(type='con', mid=coap_message2['mid'], tok=coap_message2['tok'], code=2.04,
                          pl='test payload server',
                          opt=CoAPOptionList([CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send 2 : *****')
    print(coap_response2)
    # send response
    msg, msg_bytes2 = coap_response2.build_message()
    connexion.sendto(msg_bytes2, (addr2[0], addr2[1]))

    # receive response
    msg_recv3, addr3 = connexion.recvfrom(1024)
    # translate message
    binary_msg3 = Message(msg_recv3, CoAP)
    coap_message3 = binary_msg3.get_value()
    print('***** SERVER What we receive 3 : *****')
    print(coap_message3)
    # build response
    coap_response3 = CoAP(type='con', mid=coap_message3['mid'], tok=coap_message3['tok'], code=2.05,
                          pl=coap_message2['pl'],
                          opt=CoAPOptionList([CoAPOptionETag(2), CoAPOptionUriPath(val='validate'), CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send 3 : *****')
    print(coap_response3)
    # send response
    msg, msg_bytes3 = coap_response3.build_message()
    connexion.sendto(msg_bytes3, (addr3[0], addr3[1]))

    # receive response
    msg_recv4, addr4 = connexion.recvfrom(1024)
    # translate message
    binary_msg4 = Message(msg_recv4, CoAP)
    coap_message4 = binary_msg4.get_value()
    print('***** SERVER What we receive 4 : *****')
    print(coap_message4)
    # build response
    coap_response4 = CoAP(type='con', mid=coap_message4['mid'], tok=coap_message4['tok'], code=2.04,
                          pl='test payload server3',
                          opt=CoAPOptionList(
                              [CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send 4 : *****')
    print(coap_response4)
    # send response
    msg, msg_bytes4 = coap_response4.build_message()
    connexion.sendto(msg_bytes4, (addr4[0], addr4[1]))

    # receive response
    msg_recv5, addr5 = connexion.recvfrom(1024)
    # translate message
    binary_msg5 = Message(msg_recv5, CoAP)
    coap_message5 = binary_msg5.get_value()
    print('***** SERVER What we receive 5 : *****')
    print(coap_message5)
    # build response
    coap_response5 = CoAP(type='con', mid=36, tok=b'36', code=4.12,
                          pl='test payload server3',
                          opt=CoAPOptionList([CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send 5 : *****')
    print(coap_response5)
    # send response
    msg, msg_bytes5 = coap_response5.build_message()
    connexion.sendto(msg_bytes5, (addr5[0], addr5[1]))

    connexion.close()

def td_coap_core_23_PASS_client_emulator():
    #DONT WORK
    coap_msg1 = CoAP(type='con', code='put', mid=9, tok=b'02',pl='test payload client1', opt=CoAPOptionList([CoAPOptionIfNoneMatch(), CoAPOptionUriPath(val='create1'), CoAPOptionContentFormat(0)]))
    print('***** CLIENT What we send 1 : *****')
    print(coap_msg1)
    msg, msg_bytes1 = coap_msg1.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.sendto(msg_bytes1, (IP,UDP_PORT))
    #receive message
    reply1 = sock.recv(1024)
    #translate message
    binary_msg1 = Message(reply1, CoAP)
    coap_message1 = binary_msg1.get_value()
    print('***** CLIENT What we receive 1 : *****')
    print(coap_message1)

    coap_msg2 = CoAP(type='con', code='put', mid=10, tok=b'03',pl='test payload client2',
                          opt=CoAPOptionList(
                              [CoAPOptionContentFormat(0), CoAPOptionUriPath(val='create1'), CoAPOptionIfNoneMatch()]))

    print('***** CLIENT What we send 2 : *****')
    print(coap_msg1)
    msg, msg_bytes2 = coap_msg2.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes2, (IP, UDP_PORT))
    # receive message
    reply2 = sock.recv(1024)
    # translate message
    binary_msg2 = Message(reply2, CoAP)
    coap_message2 = binary_msg2.get_value()
    print('***** CLIENT What we receive 2 : *****')
    print(coap_message2)


    sock.close()

def td_coap_core_23_FAIL_client_emulator():
    #DONT WORK
    coap_msg1 = CoAP(type='con', code='put', mid=9, tok=b'02',pl='test payload client1', opt=CoAPOptionList([CoAPOptionIfNoneMatch(), CoAPOptionUriPath(val='create1'), CoAPOptionContentFormat(0)]))
    print('***** CLIENT What we send 1 : *****')
    print(coap_msg1)
    msg, msg_bytes1 = coap_msg1.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.sendto(msg_bytes1, (IP,UDP_PORT))
    #receive message
    reply1 = sock.recv(1024)
    #translate message
    binary_msg1 = Message(reply1, CoAP)
    coap_message1 = binary_msg1.get_value()
    print('***** CLIENT What we receive 1 : *****')
    print(coap_message1)

    coap_msg2 = CoAP(type='con', code='put', mid=9, tok=b'02',pl='test payload client2',
                          opt=CoAPOptionList(
                              [CoAPOptionContentFormat(0), CoAPOptionUriPath(val='create1'), CoAPOptionIfNoneMatch()]))

    print('***** CLIENT What we send 2 : *****')
    print(coap_msg1)
    msg, msg_bytes2 = coap_msg2.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg_bytes2, (IP, UDP_PORT))
    # receive message
    reply2 = sock.recv(1024)
    # translate message
    binary_msg2 = Message(reply2, CoAP)
    coap_message2 = binary_msg2.get_value()
    print('***** CLIENT What we receive 2 : *****')
    print(coap_message2)


    sock.close()

def td_coap_core_23_PASS_server_emulator():
    # DONT WORK
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv1, addr1 = connexion.recvfrom(1024)
    #translate message
    binary_msg1 = Message(msg_recv1, CoAP)
    coap_message1 = binary_msg1.get_value()
    print('***** SERVER What we receive 1 : *****')
    print(coap_message1)
    #build response
    coap_response1 = CoAP(type='con', mid=coap_message1['mid'], tok=coap_message1['tok'], code=2.01,
                          pl='test payload server',
                          opt=CoAPOptionList([CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send 1 : *****')
    print(coap_response1)
    #send response
    msg, msg_bytes1 = coap_response1.build_message()
    connexion.sendto(msg_bytes1, (addr1[0], addr1[1]))

    #receive response
    msg_recv2, addr2 = connexion.recvfrom(1024)
    # translate message
    binary_msg2 = Message(msg_recv2, CoAP)
    coap_message2 = binary_msg2.get_value()
    print('***** SERVER What we receive 2 : *****')
    print(coap_message2)
    # build response
    coap_response2 = CoAP(type='con', mid=coap_message2['mid'], tok=coap_message2['tok'], code=4.12,
                          pl='')
    print('***** SERVER What we send 2 : *****')
    print(coap_response2)
    # send response
    msg, msg_bytes2 = coap_response2.build_message()
    connexion.sendto(msg_bytes2, (addr2[0], addr2[1]))

    connexion.close()

def td_coap_core_23_FAIL_server_emulator():
    # DONT WORK
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv1, addr1 = connexion.recvfrom(1024)
    #translate message
    binary_msg1 = Message(msg_recv1, CoAP)
    coap_message1 = binary_msg1.get_value()
    print('***** SERVER What we receive 1 : *****')
    print(coap_message1)
    #build response
    coap_response1 = CoAP(type='con', mid=coap_message1['mid'], tok=coap_message1['tok'], code=2.01,
                          pl='test payload server',
                          opt=CoAPOptionList([CoAPOptionContentFormat(0)]))
    print('***** SERVER What we send 1 : *****')
    print(coap_response1)
    #send response
    msg, msg_bytes1 = coap_response1.build_message()
    connexion.sendto(msg_bytes1, (addr1[0], addr1[1]))

    #receive response
    msg_recv2, addr2 = connexion.recvfrom(1024)
    # translate message
    binary_msg2 = Message(msg_recv2, CoAP)
    coap_message2 = binary_msg2.get_value()
    print('***** SERVER What we receive 2 : *****')
    print(coap_message2)
    # build response
    coap_response2 = CoAP(type='con', mid=36, tok=b'36', code=4.1,
                          pl='')
    print('***** SERVER What we send 2 : *****')
    print(coap_response2)
    # send response
    msg, msg_bytes2 = coap_response2.build_message()
    connexion.sendto(msg_bytes2, (addr2[0], addr2[1]))

    connexion.close()

def td_coap_core_31_PASS_client_emulator():
    #DONT WORK
    coap_msg1 = CoAP(type='con', code=0, mid=9, tok=0)
    print('***** CLIENT What we send 1 : *****')
    print(coap_msg1)
    msg, msg_bytes1 = coap_msg1.build_message()
    # build and send CoAP/UDP/IPv4 message
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.sendto(msg_bytes1, (IP,UDP_PORT))
    #receive message
    reply1 = sock.recv(1024)
    #translate message
    binary_msg1 = Message(reply1, CoAP)
    coap_message1 = binary_msg1.get_value()
    print('***** CLIENT What we receive 1 : *****')
    print(coap_message1)

    sock.close()

def td_coap_core_31_PASS_server_emulator():
    # DONT WORK
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv1, addr1 = connexion.recvfrom(1024)
    #translate message
    binary_msg1 = Message(msg_recv1, CoAP)
    coap_message1 = binary_msg1.get_value()
    print('***** SERVER What we receive 1 : *****')
    print(coap_message1)
    #build response
    coap_response1 = CoAP(type=3, mid=coap_message1['mid'], tok=coap_message1['tok'], code=0)
    print('***** SERVER What we send 1 : *****')
    print(coap_response1)
    #send response
    msg, msg_bytes1 = coap_response1.build_message()
    connexion.sendto(msg_bytes1, (addr1[0], addr1[1]))

    connexion.close()

def td_coap_core_31_FAIL_PL_server_emulator():
    # DONT WORK
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv1, addr1 = connexion.recvfrom(1024)
    #translate message
    binary_msg1 = Message(msg_recv1, CoAP)
    coap_message1 = binary_msg1.get_value()
    print('***** SERVER What we receive 1 : *****')
    print(coap_message1)
    #build response
    coap_response1 = CoAP(type=3, mid=coap_message1['mid'], tok=coap_message1['tok'], code=0, pl='test')
    print('***** SERVER What we send 1 : *****')
    print(coap_response1)
    #send response
    msg, msg_bytes1 = coap_response1.build_message()
    connexion.sendto(msg_bytes1, (addr1[0], addr1[1]))

    connexion.close()

def td_coap_core_31_FAIL_TOK_server_emulator():
    # DONT WORK
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv1, addr1 = connexion.recvfrom(1024)
    #translate message
    binary_msg1 = Message(msg_recv1, CoAP)
    coap_message1 = binary_msg1.get_value()
    print('***** SERVER What we receive 1 : *****')
    print(coap_message1)
    #build response
    coap_response1 = CoAP(type=3, mid=coap_message1['mid'], tok=b'01', code=0)
    print('***** SERVER What we send 1 : *****')
    print(coap_response1)
    #send response
    msg, msg_bytes1 = coap_response1.build_message()
    connexion.sendto(msg_bytes1, (addr1[0], addr1[1]))

    connexion.close()

def td_coap_core_31_FAIL_CODE_server_emulator():
    # DONT WORK
    # waiting for receive a message CoAP/UDP/IPv4
    connexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connexion.bind((IP, UDP_PORT))
    msg_recv1, addr1 = connexion.recvfrom(1024)
    #translate message
    binary_msg1 = Message(msg_recv1, CoAP)
    coap_message1 = binary_msg1.get_value()
    print('***** SERVER What we receive 1 : *****')
    print(coap_message1)
    #build response
    coap_response1 = CoAP(type=3, mid=coap_message1['mid'], tok=coap_message1['tok'], code=2.00)
    print('***** SERVER What we send 1 : *****')
    print(coap_response1)
    #send response
    msg, msg_bytes1 = coap_response1.build_message()
    connexion.sendto(msg_bytes1, (addr1[0], addr1[1]))

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
        _launch_sniffer('tmp/TD_COAP_CORE_23_fail.pcap')
        time.sleep(2)
        # td_coap_core_01_PASS_server_emulator()
        t1 = threading.Thread(target=td_coap_core_23_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_23_PASS_client_emulator)

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
        
        #give none
        t1 = threading.Thread(target=td_coap_core_10_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_10_FAIL_TOK_0_BYTE_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_10_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_10_FAIL_TOK_9_BYTE_client_emulator)

        t1 = threading.Thread(target=td_coap_core_10_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_10_PASS_client_emulator)
        
        #test case 11
        t1 = threading.Thread(target=td_coap_core_11_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_11_PASS_client_emulator)
        
        #give none
        t1 = threading.Thread(target=td_coap_core_11_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_11_FAIL_TOK_0_BYTE_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_11_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_11_FAIL_TOK_9_BYTE_client_emulator)

        t1 = threading.Thread(target=td_coap_core_11_FAIL_NO_TOK_server_emulator)
        t2 = threading.Thread(target=td_coap_core_11_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_11_FAIL_NO_PL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_11_PASS_client_emulator)
        
        #test case 12
        t1 = threading.Thread(target=td_coap_core_12_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_12_PASS_client_emulator)

        t1 = threading.Thread(target=td_coap_core_12_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_12_PASS_client_emulator)
        
        #test case 13, utiliser le serveure java de coap testting tool pour généré le pass
        t1 = threading.Thread(target=td_coap_core_13_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_13_PASS_client_emulator)

        t1 = threading.Thread(target=td_coap_core_13_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_13_FAIL_client_emulator)
        
        #test case 14
        t1 = threading.Thread(target=td_coap_core_14_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_14_PASS_client_emulator)
        
        #inconclusive
        t1 = threading.Thread(target=td_coap_core_14_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_14_FAIL_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_14_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_14_PASS_client_emulator)
        
        #test case 15
        
        #test case 16
        
        #test case 17
        t1 = threading.Thread(target=td_coap_core_17_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_17_PASS_client_emulator)

        t1 = threading.Thread(target=td_coap_core_17_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_17_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_17_FAIL_ACK_server_emulator)
        t2 = threading.Thread(target=td_coap_core_17_PASS_client_emulator)
        
        #test case 18
        t1 = threading.Thread(target=td_coap_core_18_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_18_PASS_client_emulator)
        
        #inconclusive
        t1 = threading.Thread(target=td_coap_core_18_FAIL_2_location_server_emulator)
        t2 = threading.Thread(target=td_coap_core_18_PASS_client_emulator)
        
        #inconclusive
        t1 = threading.Thread(target=td_coap_core_18_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_18_PASS_client_emulator)
        
        #test case 19
        t1 = threading.Thread(target=td_coap_core_19_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_19_PASS_client_emulator)

        t1 = threading.Thread(target=td_coap_core_19_PASS_NO_PL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_19_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_19_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_19_PASS_client_emulator)
        
        #inconclusive
        t1 = threading.Thread(target=td_coap_core_19_FAIL_WRONG_OPT_server_emulator)
        t2 = threading.Thread(target=td_coap_core_19_PASS_client_emulator)
        
        #test case 20
        t1 = threading.Thread(target=td_coap_core_20_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_20_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_20_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_20_FAIL_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_20_FAIL_WRONG_FORMAT_server_emulator)
        t2 = threading.Thread(target=td_coap_core_20_PASS_client_emulator)
        
        #test case 21
        t1 = threading.Thread(target=td_coap_core_21_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_21_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_21_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_21_FAIL_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_21_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_21_PASS_client_emulator)
        
        #test case 22
        t1 = threading.Thread(target=td_coap_core_22_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_22_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_22_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_22_FAIL_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_22_FAIL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_22_PASS_client_emulator)
        
        #test case 23
        t1 = threading.Thread(target=td_coap_core_23_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_23_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_23_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_23_PASS_client_emulator)
        
        #test case 31
        t1 = threading.Thread(target=td_coap_core_31_PASS_server_emulator)
        t2 = threading.Thread(target=td_coap_core_31_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_31_FAIL_PL_server_emulator)
        t2 = threading.Thread(target=td_coap_core_31_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_31_FAIL_CODE_server_emulator)
        t2 = threading.Thread(target=td_coap_core_31_PASS_client_emulator)
        
        t1 = threading.Thread(target=td_coap_core_31_FAIL_TOK_server_emulator)
        t2 = threading.Thread(target=td_coap_core_31_PASS_client_emulator)
        
        """


if __name__ == "__main__":

    main(sys.argv[1:])

