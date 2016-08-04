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

from ttproto.core.typecheck import *

class Error (Exception):
	"""Generic Error exception"""

	def __init__ (self, *msg):
		"""Initialise the exception with an error message

		The elements of *msg are converted into strings separated by
		spaces (just like print()).

		If msg is empty, the error message is replaced with the name of
		the exceptiontype: type(self).__name__
		"""

		l = ["Error:"]
		if msg:
			l.extend (msg)
		else:
			if type (self) != Error:
				l.append (type (self).__name__)
			elif not len (msg):
				l.append ("<undefined>")

		self.msg = " ".join([str(v) for v in l])

	def __str__ (self):
		"""Return the exception message"""
		return self.msg

	def __repr__ (self):
		return "%s(%s)" % (type (self).__name__, (repr(self.msg) if self.msg else ""))

class UserInterrupt (Exception):
	"""Exception thrown to notify an interruption by the user.

	Contrary to the builtin KeyboardInterrupt exception, this exception is
	not raised asynchronously. In order to allow a clean interruption.
	"""
	pass

class TerminateTestcase (Exception):
	"""Exception to be throw to terminate the execution of the testcase immediately.

	This exception is handled by the Testcase class. When caught, the execution
	stops immediately, without returning any error.
	"""
	pass

class PortNotConnected (Error):
	"""Attempt to send a message to a port which is not connected"""
	pass

# TODO: use builtin class NotImplementedError
class NotImplemented (Error):
	"""Function not implemented"""
	pass

class BadConversion (Error):
	"""Value conversion error"""
	def __init__ (self, data, type_, exc):
		desc = str(exc)[7:] if isinstance (exc, Error) else str(exc)
		Error.__init__ (self, "cannot convert %s into %s (%s)" % (type(data).__name__, type_.__name__, desc))

class DecodeError (Error):
	"""Decoding error"""
	def __init__ (self, binary, target, exc):
		location = "" if not hasattr (exc, "ttproto_location") else (" at " + str(exc.ttproto_location))
		Error.__init__ (self, "cannot decode %s into %s (%s%s)" % (
			repr(binary),
			target.__name__,
			(str (exc) or repr (exc)),
			location))
class UnknownField (Error):
	"""Attempt to access an unknown field"""
	def __init__ (self, value, field_name):
		Error.__init__ (self, "value of type %s has no field named %s" % (type (value).__name__, repr(field_name)))


class ReaderError(Error):
    """
    Exception class for when a reader can't process the file
    """
    pass

class Location:
	"""A class to help locating encoding or decoding errors.

	When decoding a complex structured values, it is useful to know which
	field caused the errors. This allows recording the path of the errenous field.
	"""
	def __init__ (self):
		self.__path = []

	@typecheck
	def push (self, type_:type, field: optional(str) = None):
		"""Append a new field in the path

		- type_		the type of the current type structured type being processed
		- field		the name/index of the field that caused the exception
		"""
		self.__path.append ((type_, field))

	def __str__ (self):
		return "".join ("{%s}%s" % (t.__name__, ("." + f) if f else "") for t, f in reversed(self.__path))

@typecheck
def push_location (e: Exception, type_: type, field: optional(str) = None):
	"""Utility function used to report the location of encoding and decoding errors

	This function shall be called in an except clause in the
	decoder/encoder of structured values to indicate what is the current
	type and field.

	It attach a Location object into the thrown exception, to report the
	location.

	Exemple:
		def _build_message (self):
			...
			for field_name, field_value in ...:
				try:
					value, bin = field_value.build_message()
				except Exception as e:
					push_location (e, type(self), field_name)
					raise
	"""

	if not hasattr (e, "ttproto_location"):
		e.ttproto_location = Location()

	e.ttproto_location.push (type_, field)

