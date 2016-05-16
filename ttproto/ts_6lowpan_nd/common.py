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

import os, time , sys

sys.path.append('..')

from	ttproto.core.lib.all		import *
from	ttproto.core.port		import *

from	ttproto.core.logger		import *
from	ttproto.core.html_logger		import *
from	ttproto.core.control		import *
from	ttproto.core.data		import *
from	ttproto.core.snapshot		import *
from	ttproto.core.lib.ports.socat	import *
from	ttproto.core.exceptions		import TerminateTestcase

from	.config			import *
from 	.altsteps		import *
from 	.commontestsetups	import *

from ttproto.core.list			import *
from ttproto.core.templates 		import *

#FIXME: move those functions in a specific file

import fcntl, select
# make stdin a non-blocking file
stdin_fd = sys.stdin.fileno()
fcntl.fcntl(stdin_fd, fcntl.F_SETFL, fcntl.fcntl(stdin_fd, fcntl.F_GETFL) | os.O_NONBLOCK)


# FIXME : we will need a way to a add callback function, or to grab the data, at least for Test_LPND_1_1_6d,f
def receive_unordered (link, *datas):
	data_list = list (datas)
	received_values = []
	while data_list:
		with alt:
			for d in data_list:
				@link.receive (d)
				def _(data, value):
					try:
						data_list.remove(data)
					except ValueError:
						data_list.remove(data["pl"]["pl"]) # FIXME: will raise if receiving explicitely Sixlowpan(IPv6|IPHC) and/or if the data is not flat
						
					received_values.append(value)
					set_verdict ("pass")
	return received_values

def superop ( opt ):
	return Superset (ICMPv6OptionList , opt)
