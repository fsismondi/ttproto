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

"""A module for guessing a name for the objects"""

from ttproto.core.typecheck import *
import dis, inspect, opcode, os

__all__ = [
    'NamedObject',
    'get_parent_var_name',
    'skip_parent_var_name',
]


class NamedObject:
    """A class of object whose instance name will be guessed by this module

    This function will store a name for this object in its __name__
    attribute.

    This name will be set to the value of the 'name' parameter if present.
    Otherwise the function will use the result of get_parent_var_name().

    see help(get_parent_var_name)
    """

    @typecheck
    def __init__(self, name: optional(str) = None):
        self.__name__ = name if name else get_parent_var_name()


def _print_stack(st):
    i = len(st) - 1
    for l in reversed(st):
        l4 = l[4]
        print("%d. %s() in %s:%d\n  %s" % (i, l[3], l[1], l[2], "\n" if l[4] is None else l4[0]), end=' ')
        i -= 1


_OPCODES_STORE = (
    opcode.opmap['STORE_DEREF'],
    opcode.opmap['STORE_FAST'],
    opcode.opmap['STORE_GLOBAL'],
    opcode.opmap['STORE_NAME'],
)
_OPCODE_JUMP_FORWARD = opcode.opmap['JUMP_FORWARD']
_REJECTED_NEXT_OPCODES = (opcode.opmap['BUILD_TUPLE'],
                          opcode.opmap['COMPARE_OP'],
                          opcode.opmap['LOAD_CONST'],
                          opcode.opmap['LOAD_FAST'],
                          opcode.opmap['LOAD_GLOBAL'],
                          opcode.opmap['LOAD_NAME'],
                          opcode.opmap['LOAD_ATTR'],
                          opcode.opmap['LOAD_DEREF'],
                          opcode.opmap['CALL_FUNCTION'],
                          opcode.opmap['BUILD_LIST'],
                          opcode.opmap['BUILD_MAP'],
                          opcode.opmap['ROT_TWO'],
                          opcode.opmap['BINARY_TRUE_DIVIDE'],
                          opcode.opmap['PRINT_EXPR'],
                          opcode.opmap['RETURN_VALUE']  # FIXME: maybe not reject this one
                          )


def _forward_instruction(it_instructions, offset):
    for opcode in it_instructions:
        assert opcode.offset <= offset
        if opcode.offset == offset:
            return opcode


def get_parent_var_name():
    """A function that inspects the execution stack to guess the name of
    the variable in which is stored the result of the calling function.

    NOTE: this feature might be broken at any time. The scripts should not
    rely on this feature at all. Its purpose is just to bring some useful
    indicative into the test logs.

    Examples:
        >>> blah_blah_blah = NamedObject()
        >>> blah_blah_blah.__name__
        'blah_blah_blah'

        >>> NamedObject().__name__
        '(anon)'

        >>> IPv6_multicast = IPv6(dst=IPv6Prefix("ff00::/8"))
        >>> IPv6_multicast.__name__
        'IPv6_multicast'
    """  # identify the frame of the caller of the parent function
    name = "(anon)"
    self = None
    try:
        stack = inspect.stack()
        #		_print_stack (stack)
        #		print stack[3]
        #		f = stack[3][0]
        #		print f.f_locals
        #		print dir(f)
        #		for par in 'co_argcount', 'co_cellvars', 'co_consts', 'co_filename', 'co_firstlineno', 'co_flags', 'co_freevars', 'co_lnotab', 'co_name', 'co_names', 'co_nlocals', 'co_stacksize', 'co_varnames':
        #			print "%s: %s" % (par, getattr (f.f_code, par))
        #
        #		print "-------------------------------------------------------\n"
        id = 1
        while True:
            id_next = id + 1
            layer = stack[id]
            func = layer[3]
            frame = layer[0]

            # will be set if this function is enclosed by a fake_function_skip_parent_var_name
            # from a @skip_parent_var_name
            skip_tagged = False

            try:
                if func == "type_definition":
                    name = frame.f_locals["cls"].__name__
                    raise IndexError()

                # check if this function is tagged with @typecheck
                if stack[id_next][3] == "typecheck_invocation_proxy":
                    # skip it
                    id_next += 1

                # check if this function is tagged with @skip_parent_var_name
                if stack[id_next][3] == "fake_function_skip_parent_var_name":
                    # skip it
                    id_next += 1
                    skip_tagged = True

            except IndexError:
                pass

            if not skip_tagged:
                # if the calling function is a constructor
                # then we will skip the parent callers if they are
                # constructors for the same object
                if func == '__init__' and frame.f_code.co_argcount:
                    f_self = frame.f_locals[frame.f_code.co_varnames[0]]
                    if id == 1:
                        self = f_self
                    elif not self is f_self:
                        # different object, we stop here
                        break
                else:
                    # this function is not tagged and is not a constructor
                    # -> end of recursion
                    break

            id = id_next

        #print ("frame id:", id)
        code = frame.f_code.co_code
        it_instructions = dis.get_instructions(frame.f_code)

        istr = _forward_instruction(it_instructions, frame.f_lasti)
        #print ("istr", istr)

        if istr.opname.startswith("CALL_"):
            istr = next(it_instructions)
            #print ("next", istr)
        else:
            raise Error("Current instruction is %d %s but should be a function call" % (currop, opcode.opname[currop]))
        while istr.opcode == _OPCODE_JUMP_FORWARD:
            istr = _forward_instruction(it_instructions, istr.argval)
            #print ("next", istr)
         
        nextop = istr.opcode
        #print ("nextop", opcode.opname [nextop])

        if nextop in _OPCODES_STORE:
            name = istr.argval
        else:
            if nextop not in _REJECTED_NEXT_OPCODES:
                _print_stack(stack)
                print("Now in frame", id)
                print("Warning: cannot guess the caller var name (opcode: %d %s)" % (nextop, opcode.opname[nextop]))
                global frame_fail
                frame_fail = frame

    except IndexError:
        #		print "IndexError"
        pass

    # print ("Result:", name)
    return name


def skip_parent_var_name(func):
    """A decorator for functions that should be skipped by
    get_parent_var_name() when inspecting the stack.

    Example:
        >>> def some_factory_function():
        ...   result = NamedObject()
        ...   return result
        ...
        >>> @skip_parent_var_name
        ... def some_smart_factory_function():
        ...   smart_result = NamedObject()
        ...   return smart_result
        ...
        >>> foo = some_factory_function()
        >>> foo.__name__
        'result'
        >>> bar = some_smart_factory_function()
        >>> bar.__name__
        'bar'
    """

    def fake_function_skip_parent_var_name(*k, **kw):
        return func(*k, **kw)

    return fake_function_skip_parent_var_name
