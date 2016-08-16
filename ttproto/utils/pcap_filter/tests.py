from ttproto.utils.pure_pcapy import *
from ttproto.core.dissector import *

if __name__ == '__main__':
    filename = 'tests/test_dumps/6lowpan/echo_req_and_reply_and_other_packets_with_openmote_sniffer.pcap'
    reader = open_offline(filename)


    # for OPENWSN captures need to ignore the first 5*16 bytes (as it always generates raw:ipv6:udp:zep:wpan)
    JUMP_LENGTH = 16*5 #en bytes
    #dumper = reader.dump_open('temp.pcap')

    dumper = Dumper('temp.pcap', 200, DLT_IEEE802_15_4)
    count = 0
    stop_iter = False
    while not stop_iter:
        try:
            new_header , new_data =  reader.next()
            if not new_header:
                break

            count += 1
            print(count)
            new_header.incl_len = new_header.incl_len - JUMP_LENGTH
            new_header.orig_len = new_header.incl_len
            new_data = new_data[JUMP_LENGTH:] # take from jumplength bytes to the end of the data
            dumper.dump(new_header , new_data)

        except PcapError:
            print('the filtering has reached the end of the file :D, pakcet count %d'% count)
            break
    print('starting dissection')
    dissector = Dissector('temp.pcap')
    for s in dissector.summary():
        print(s)