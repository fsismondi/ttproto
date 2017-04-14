import socket, logging, platform, os, subprocess, time
from ttproto.core.lib.all	import *
from ttproto.core.data	import *


logger = logging.getLogger(__name__)

"""
PRECONDITIONS:
- Have a running CoAP server at 127.0.0.1:5683, with the /resurces configured in TD_COAP ETSI doc.
- have tcpdump installed
"""

IP='127.0.0.1'
UDP_PORT=5683

def td_coap_core_01_PASS_client_emulator():
    coap_msg =  CoAP(type='con', code='get', opt= CoAPOptionList([CoAPOptionUriPath ("test")]))
    #coap_msg = CoAP(type='con', code='get')
    msg, msg_bytes = coap_msg.build_message()
    # build and send CoAP/UDP/IPv6 message
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.sendto (msg_bytes, (IP,UDP_PORT))
    reply = sock.recv(10)
    sock.close()

    return reply



def _launch_sniffer(filename, filter_if = None, filter_proto = None):
    logger.info('Launching packet capture..')

    if filter_proto is None:
        filter_proto = ''

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

    params = 'tcpdump ' + filter_proto+ ' -K -i ' + filter_if + ' -s 200 ' + ' -U -w ' + filename + '  -vv ' + '&'
    os.system(params)
    logger.info('creating process tcpdump with: %s' % params)
    # TODO we need to catch tcpdump: <<tun0: No such device exists>> from stderr

    return True


def _stop_sniffer():
    proc = subprocess.Popen(["pkill", "-INT", "tcpdump"], stdout=subprocess.PIPE)
    proc.wait()
    logger.info('Packet capture stopped')
    return True


if __name__ == "__main__":
    _launch_sniffer('tmp/TD_COAP_CORE_01_pass.pcap',filter_proto='coap')
    time.sleep(2)
    respose = td_coap_core_01_PASS_client_emulator()
    _stop_sniffer()
    time.sleep(1)
    print(respose)