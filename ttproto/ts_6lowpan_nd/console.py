#!/usr/local/bin/python3 -i
#!/usr/bin/python3 -i
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
import rlcompleter, readline
readline.parse_and_bind('tab: complete')

from .common import *
from	ttproto.core.lib.all	import *
import	atexit, os, sys

__HISTORY_FILE = os.path.join (os.path.expanduser ("~"), ".ttproto_history")

class Console:
	"""Welcome to ttproto console.
- Use [tab] to complete
- Use help(object) to print help messages.
- Quit using ctrl+d"""
	pass

def help( obj ):
	if obj.__doc__ is not None:
		print( obj.__doc__)
	else:
		print("undocumented")


def save_history():
	readline.write_history_file(__HISTORY_FILE)

help(Console)

try:
	readline.read_history_file (__HISTORY_FILE)
except IOError:
	pass

atexit.register (save_history)

for v in sys.argv[1:]:
	readline.add_history (v)
	print (">>>", v)
	exec (v)


