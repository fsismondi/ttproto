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

import atexit, threading, tempfile, os, signal, socket, time, weakref, traceback

from ttproto.core.typecheck import *
from ttproto.core.data import *
from ttproto.core import exceptions, port, clock

from ttproto.core.lib.ethernet import Ethernet
from ttproto.core.lib.encap import *

import ttproto.utils.pure_pcapy as pure_pcapy

_map_link_type = {
    pure_pcapy.DLT_EN10MB: Ethernet,
    pure_pcapy.DLT_LINUX_SLL: LinuxCookedCapture,
    pure_pcapy.DLT_NULL: NullLoopback,
}


class PcapReader:
    @typecheck
    def __init__(self, file: str, decode_type: optional(is_type) = None):

        self.__pcap_file = open(file, "rb")
        self.__reader = pure_pcapy.Reader(self.__pcap_file)
        # print ("datalink: %d" % self.__reader.datalink())

        if not decode_type:
            try:
                decode_type = _map_link_type[self.__reader.datalink()]
            except KeyError:
                decode_type = bytes

        self.__decode_type = get_type(decode_type)

    def __del__(self):
        # Close the file only if it was opened before
        # if hasattr(self, '__pcap_file'):
        self.__pcap_file.close()

    def next(self):

        h, b = self.__reader.next()

        if not h:
            return None

        # timestamp
        ts = h.getts()
        ts = ts[0] + ts[1] * 0.000001

        # decode the packet
        try:
            m = Message(b, self.__decode_type)
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


class PcapPort(port.RawMessagePort):
    @typecheck
    def __init__(self, file: str, decode_type: optional(is_type) = None, clock_: optional(clock.Clock) = None,
                 endpoint: optional(port.BaseMessagePort) = None):

        self.__reader = pure_pcapy.Reader(open(file, "rb"))
        self.__clock = clock_ if clock_ else clock.Clock.get_instance()

        if not decode_type:
            try:
                decode_type = _map_link_type[self.__reader.datalink()]
            except KeyError:
                decode_type = bytes

        port.RawMessagePort.__init__(self, decode_type, endpoint)

        self.__schedule_next()

    def __schedule_next(self):

        h, self.__next_packet = self.__reader.next()

        if h:
            # timestamp
            ts = h.getts()
            ts = ts[0] + ts[1] * 0.000001

            # schedule
            self.__clock.schedule_event_absolute(ts, self.__callback)

    def __callback(self):
        self._forward(self.__next_packet)

        self.__schedule_next()

    def enqueue(self, msg):
        raise Exception("PcapPort is receive-only")
