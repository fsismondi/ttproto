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

from ttproto.utils.pure_pcapy import *
from ttproto.core.typecheck import *

# TODO extend to other types of profiles which involve sth different that removing the first X bytes of each frame
# TODO filter first X layers of pcap
# TODO protocol filter: ex: filter anything that's not IEE802.15.4? dissect()  already does this


@typecheck
def remove_first_bytes( pcap_filename : str, new_pcap_filename: str , number_of_bytes: int, new_snaplen: int, new_network):

    reader = open_offline(pcap_filename)
    dumper = Dumper(new_pcap_filename, new_snaplen, new_network)

    count = 0
    stop_iter = False

    while not stop_iter:
        try:
            new_header , new_data =  reader.next()
            if not new_header:
                break
            count += 1
            new_header.incl_len = new_header.incl_len - number_of_bytes
            new_header.orig_len = new_header.incl_len
            new_data = new_data[number_of_bytes:] # take from jumplength bytes to the end of the data
            dumper.dump(new_header , new_data)

        except PcapError:
            print('the filtering has reached the end of the file :D, pakcet count %d'% count)
            break




