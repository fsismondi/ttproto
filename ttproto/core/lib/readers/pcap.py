#!/usr/bin/env python3
#
#   (c) 2012  Universite de Rennes 1
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

from ttproto.core.data import *
from ttproto.utils import pure_pcapy
import logging

from ttproto.core.typecheck import *
from ttproto.core.lib.ethernet import Ethernet
from ttproto.core.lib.encap import *
from ttproto.core.lib.inet.ipv6 import IPv6
from ttproto.core.lib.ieee802154 import Ieee802154
from ttproto.core.lib.readers.capture_reader import CaptureReader

log = logging.getLogger(__name__)
log.setLevel(level=logging.WARNING)

_map_link_type = {
    pure_pcapy.DLT_LINUX_SLL: LinuxCookedCapture,
    pure_pcapy.DLT_NULL: NullLoopback,
    pure_pcapy.DLT_EN10MB: Ethernet,
    pure_pcapy.DLT_IEEE802_15_4: Ieee802154,
    pure_pcapy.DLT_IEEE802_15_4_NOFCS: Ieee802154,
    # TODO DLT_RAW could be ipv4, need to do some introspection of packet before mapping this DLT
    pure_pcapy.DLT_RAW: IPv6
    # pure_pcapy.DLT_IEEE802_15_4_NONASK_PHY: Ieee802154
}


class PcapReader(CaptureReader):
    """
    Reader class for pcap capture files
    """

    @typecheck
    def __init__(self, file: str):
        """
        Initialize the reader with the corresponding file

        :param file: The path to the file to read
        :type file: str
        """

        self.__pcap_file = open(file, 'rb')
        try:
            self.__reader = pure_pcapy.Reader(self.__pcap_file)
        except Exception as e:
            self.__pcap_file.close()
            raise e
        log.debug("datalink: %d" % self.__reader.datalink())

        try:
            decode_type = _map_link_type[self.__reader.datalink()]
        except KeyError:
            decode_type = bytes

        self.__decode_type = get_type(decode_type)

    def __del__(self):
        # Close the file only if it was opened before
        try:
            self.__pcap_file.close()
        except:
            pass

    def next(self):

        h, b = self.__reader.next()

        if not h:
            return None

        # timestamp
        ts = h.getts()
        ts = ts[0] + ts[1] * 0.000001

        # decode the packet
        try:
            log.debug('Decoding bytes as %s: %s ' % (repr(b), self.__decode_type))
            m = Message(b, self.__decode_type)
            #log.debug(m.display())
            exc = None
        except Exception as e:
            m = Message(b)
            exc = e

        return ts, m, exc

    def __iter__(self):
        while True:
            f = self.next()

            if not f:
                return

            yield f
