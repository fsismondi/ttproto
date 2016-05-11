#!/usr/bin/env python3

from ttproto.core import typecheck3000
from ttproto.core.typecheck3000 import *

'''
TODO: hack typeckeck3000 to display the line number locating the function
that threw the exception

TODO: implémenter un typecheck_inherit
'''

#TODO: implement it
this_class = anything


__all__ = list(typecheck3000.__all__)
__all__.append("this_class")



from ttproto.core.typecheck3000 import iterable	# missing symbol (TODO: bug report)
__all__.append ("iterable")

#typecheck3000.disable()

