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

from	ttproto.core.typecheck	import *
from	ttproto.core.data	import *

__all__ = [
	"SubtypeClass",
]

def SubtypeClass (pattern: is_data):

	pattern = as_data (pattern)
	base	= pattern.get_type()

	# FIXME: there is no way to automatically check that the value is valid
	#	 (e.g. at initialisation or when the object is updated)
	#	 -> would require some notification function when something is updated
	#	    (especially in the constructors)
	class SubtypeValue (base):
		@staticmethod
		def get_base_type():
			return base

		@classmethod
		def is_valid_value (cls, value):
			return super (SubtypeValue, cls).is_valid_value (value) and pattern.match (value)

	def SubtypeMetaclass (name, bases, classdict):
			assert len (bases) == 0 # FIXME: it could be useful to have multiple inheritance in some cases ?
			return type (name, (SubtypeValue,), classdict)

	return SubtypeMetaclass

