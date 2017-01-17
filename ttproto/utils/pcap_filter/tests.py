#!/usr/bin/env python3
#
#  (c) 2012  Universite de Rennes 1
#
# Contact address: <t3devkit@irisa.fr>
#
#
# This software is governed by the CeCILL license under French law and
# abiding by the rules of distribution of free software.  You can  use,
# modify and/or redistribute the software under the terms of the CeCILL
# license as circulated by CEA, CNRS and INRIA at the following URL
# "http://www.cecill.info".
#
# As a counterpart to the access to the source code and  rights to copy,
# modify and redistribute granted by the license, users are provided only
# with a limited warranty  and the software's author,  the holder of the
# economic rights,  and the successive licensors  have only  limited
# liability.
#
# In this respect, the user's attention is drawn to the risks associated
# with loading,  using,  modifying and/or developing or reproducing the
# software by the user in light of its specific status of free software,
# that may mean  that it is complicated to manipulate,  and  that  also
# therefore means  that it is reserved for developers  and  experienced
# professionals having in-depth computer knowledge. Users are therefore
# encouraged to load and test the software's suitability as regards their
# requirements in conditions enabling the security of their systems and/or
# data to be ensured and,  more generally, to use and operate it in the
# same conditions as regards security.
#
# The fact that you are presently reading this means that you have had
# knowledge of the CeCILL license and that you accept its terms.

from ttproto.utils.pure_pcapy import DLT_IEEE802_15_4
from ttproto.core.lib.all import Ieee802154
from ttproto.utils.pcap_filter import remove_first_bytes, openwsn_profile_filter, finterop_tun_profile_filter

if __name__ == '__main__':

    # from ttproto.core.dissector import Dissector
    #
    # #filename = 'tests/test_dumps/6lowpan/echo_req_and_reply_and_other_packets_with_openmote_sniffer.pcap'
    #
    # openwsn_profile_filter(filename)
    #
    # print('starting dissection')
    # dissector = Dissector('tmp/temp.pcap')
    #
    # for s in dissector.summary():
    #     print(s)
    #
    # print("\n Ieee802154 frames: \n")
    #
    # for s in dissector.summary(protocol = Ieee802154):
    #     print(s)

    from ttproto.core.dissector import Dissector

    #filename = 'tmp/ipv6_loopback_icmp6.pcap'
    #filename = 'tmp/loopback_1e00_ipv6.pcap'
    #filename = 'tmp/tun_sniffed_coap_switch_endiannes.pcap'
    #filename = 'tmp/tun_sniffed_coap.pcap'
    filename = '/Users/fsismondi/TD_COAP_CORE_01.pcap'

    # dissect with no modifs
    dissector = Dissector(filename)

    # dissect with filter
    finterop_tun_profile_filter(filename)
    #dissector = Dissector('tmp/temp.pcap')
    print(dissector.summary())
    print('#####')
    print(dissector.dissect())

