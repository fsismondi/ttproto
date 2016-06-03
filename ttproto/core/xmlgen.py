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

import io, sys, types
from xml.sax import saxutils

from	ttproto.core.typecheck	import *

__all__ = [
	'XMLGeneratorControl',
	'XMLGenerator',
	'XHTML10Generator',
]

class XMLGeneratorControl:
	def __init__(self, generator):
		self.__gen = generator

	def flush (self):
		self.__gen._XMLGenerator__file.flush()

	def write (self, txt):
		self.__gen._XMLGenerator__file.write (saxutils.escape (txt))

	def raw_write (self, txt):
		self.__gen._XMLGenerator__file.write (txt)

class XMLGenerator:
	@typecheck
	def __init__ (self, root:	str,
			output:		either (str, io.TextIOBase)	= sys.stdout,
			indented:	bool				= False,
			encoding:	str				= "UTF-8",
			dtd:		optional (tuple_of (str))	= None,
			attr:		dict_of (str, str)		= {}):

		if dtd:
			assert 2 <= len (dtd) <= 3
			assert dtd[0] in ("SYSTEM", "PUBLIC")

		self.__root = root
		self.__root_attr = attr

		if isinstance (output, str):
			self.__file = open (output, "w")
			self.__autoclose = True
		else:
			self.__file = output
			self.__autoclose = False


		self.__last = None
		self.__previous = None
		self.__parent = None
		self.__root_elem = None
		self.__level = 0

		if not indented:
			self.__write     = self.__file.write
			self.__write_txt = self.__file.write

		self.__write ('<?xml version="1.0" encoding="%s"?>' % encoding)

		self.__write ('<!DOCTYPE %s %s>' % (root,
				(('%s "%s" "%s"' if len (dtd) == 3 else '%s "%s"') % dtd)
			))


	def __enter__ (self):
		self.__root_elem = True	# to avoid assertion error in __getattr__
		self.__root_elem = getattr (self, self.__root)
		self.__root_elem (**self.__root_attr)
		self.__root_elem.__enter__()
		return self

	def __exit__ (self, a, b, c):
		self.__root_elem.__exit__(a, b, c)
		if self.__autoclose:
			self.__file.close()

	def __push (self, elem):
		# must be a child of elem.__parent
		assert elem._Elem__next == self.__parent
		assert self.__last == elem
		if repr(elem) == "<a>":
			raise

		self.__flush_previous()

		self.__last = None

		self.__parent = elem

		self.__status("doc push")

	def __pop (self, next_elem):

		self.__flush_last()
		self.__parent = next_elem

		self.__status("doc pop")

	def __replace (self, new_last):
		# must be a child of elem.__parent
		assert new_last._Elem__parent == self.__last

		self.__flush_previous()

		self.__last = new_last
		self.__status("doc replace")


	def __getattr__ (self, name):
		assert self.__root_elem		# must call __enter__ first

		self.__flush_previous()

		self.__previous = self.__last
		self.__last = XMLGenerator.__Elem (self, self.__parent, name)
		self.__status("doc attr")
		return self.__last

	def __status (self, txt):
#		print ("\t\t\t%-10s:	elem=%-10s last=%-10s previous=%-10s" % (txt, self.__parent, self.__last, self.__previous))
		pass

	def __flush_previous (self):
		if self.__previous:
			last, prev = self.__last, self.__previous
			self.__last, self.__previous = None, None
			prev._Elem__flush()
			self.__last = last

		self.__status("doc flush prev")

	def __flush_last (self, last = None):
		self.__flush_previous()
		if self.__last and self.__last is not last:
			self.__last._Elem__flush()
		self.__last = None
		self.__status("doc flush last")

	@typecheck
	def __call__ (self, txt):
		self.__write_txt (saxutils.escape (str (txt)))

	def __write_txt (self, txt):
		if txt[-1] == "\n":
			self.__write (txt[:-1])
		else:
			self.__write (txt)

	@typecheck
	def __write (self, txt: str):
		assert self.__level >= 0

		print (" " * self.__level, txt, sep="", file=self.__file)

	def __write_enter (self, txt):
		self.__write (txt)
		self.__level += 1

	def __write_exit (self, txt):
		self.__level -= 1
		self.__write (txt)

	class __Elem:
		def __init__ (self, generator, next_, name):
			self.__generator = generator
			self.__next = next_
			self.__name = name
			self.__flushed = False
			self.__attr = ""
			self.__parent = None

		def __call__ (__self, __txt = None, **__kw):
			if __kw:
				assert not __self.__attr

				__self.__attr = " " + " ".join ((("%s=\"%s\"" % (k,v)) for k,v in __kw.items()))

			if __txt is None:
				return __self
			else:
				assert __self.__flushed == False

				__self.__generator._XMLGenerator__flush_last (__self)
				try:
					__self.__open()
					__self.__generator._XMLGenerator__write (saxutils.escape (str (__txt)))
				finally:
#					print ("\t\t\tfinally call", sys.exc_info())
					__self.__close()

				return None

		def __enter__ (self):
			self.__generator._XMLGenerator__push (self)

			self.__open()

		def __open (self):
			assert not self.__flushed

			self.__generator._XMLGenerator__write_enter ("<%s%s>" % (self.__name, self.__attr))
			self.__flushed = True


		def __flush (self):
			assert not self.__flushed
			self.__generator._XMLGenerator__flush_last (self)
			self.__generator._XMLGenerator__write ("<%s%s/>" % (self.__name, self.__attr))
			self.__flushed = True
			self.__name = None

			self.__close()

		def __exit__ (self, a=None, b=None, c=None):
#			print ("\t\t\texit", self, a, b, c)

			if self.__name:
				self.__close()

			self.__generator._XMLGenerator__pop (self.__next)

		def __close (self):
			if self.__name:
				self.__generator._XMLGenerator__flush_last()
				self.__old_name = self.__name

				self.__generator._XMLGenerator__write_exit ("</%s>" % self.__name)
				self.__name = None

			if self.__parent:
				self.__parent.__close()
				self.__parent = None # FIXME: is this necessary ?

		def __getattr__ (self, name):
			child = type(self) (self.__generator, self.__next, name)
			child.__parent = self

			self.__generator._XMLGenerator__replace (child)
			self.__open()
			return child

		def __repr__ (self):
			return "<%s>" % (self.__name if self.__name else self.__old_name)


def XHTML10Generator (variant = "strict", **kw):
	assert variant in ("strict", "transitional", "frameset")
	assert "dtd" not in kw
	if "attr" in kw:
		assert xmlns not in kw["attr"]
	else:
		kw["attr"] = {}

	if "root" not in kw:
		kw["root"] = "html"

	kw["attr"]["xmlns"] = "http://www.w3.org/1999/xhtml"

	if variant == "strict":
		kw["dtd"] = ("PUBLIC", "-//W3C//DTD XHTML 1.0 Strict//EN", "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd")
	elif variant == "transitional":
		kw["dtd"] = ("PUBLIC", "-//W3C//DTD XHTML 1.0 Transitional//EN", "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd")
	elif variant == "frameset":
		kw["dtd"] = ("PUBLIC", "-//W3C//DTD XHTML 1.0 Frameset//EN", "http://www.w3.org/TR/xhtml1/DTD/xhtml1-frameset.dtd")
	else:
		raise # not reachable

	return XMLGenerator (**kw)


if __name__ == "__main__":

	with XHTML10Generator() as gen:

		with gen.head:
			gen.title("pouet")

		with gen.body:
			gen.a(href="http://www.irisa.fr/tipi").img(src="truc.jpg", alt="pouet")
			with gen.p.ul:
				gen.li("truc")
				gen.li("machin")
				gen.li("bidule")
			gen.hr

			with gen.p:
				gen("bonjour\n")
				gen("\n")
				gen("ça va ?\n")

