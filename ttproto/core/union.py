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
from	ttproto.core		import exceptions

class UnionClass (type):
	@typecheck
	def __new__ (cls, name, bases, dct, types: optional(iterable) = None):

		if types is None:
			if len(bases) == 0:
				raise exceptions.Error ("UnionClass requires the 'types' parameter")

			# happens when the union is derived
			# -> just build the class
			for b in bases:
				if isinstance (b, UnionClass):
					break
			else:
				raise exceptions.Error ("UnionClass requires the 'types' parameter or that the type is derived from a type built with UnionClass")
			return type.__new__ (cls, name, bases, dct)

		assert len (bases) == 0 # TODO: maybe relax this

		bases = Value,
		result = type.__new__ (cls, name, bases, dct)
		result.__types = tuple (get_type(t) for t in types)
		return result

	def __init__ (self, name, bases, dct, types = None):
		type.__init__ (self, name, bases, dct)

	def __instancecheck__ (self, instance):
		return isinstance (instance, self.__types)

	def __subclasscheck__ (self, subclass):
		return issubclass (subclass, self.__types) or self in subclass.__mro__

