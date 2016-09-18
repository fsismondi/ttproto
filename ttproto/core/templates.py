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

import re

from ttproto.core.typecheck import *
from ttproto.core.data import *
from ttproto.core.list import ListValue

__all__ = [
    'Range',
    'ValueList',
    'AnyValue',
    'Length',
    'Superset',
    'Regex',
    'All',
    'Any',
    'Not'
]


class Range(Template):
    @typecheck
    def __init__(
        self,
        parent: either(is_data, is_type),
        lower_bound: is_flat_value,
        upper_bound: is_flat_value
    ):

        Template.__init__(self, parent)
        self.__lower = self.store_data(lower_bound)
        self.__upper = self.store_data(upper_bound)

    def _template_match(self, value):
        return self.__lower <= value <= self.__upper

    def _repr(self):
        return "%s(%s, %s, %s)" % (
            type(self).__name__,
            self.get_type().__name__,
            repr(self.__lower),
            repr(self.__upper),
        )


# TODO: rename it as Or
class ValueList(Template):

    @typecheck
    def __init__(self, parent: either(is_type, is_data), datas: iterable):

        Template.__init__(self, parent)

        self.__datas = [self.store_data(d) for d in datas]

    def _template_match(self, value):

        for d in self.__datas:
            if d.match(value):
                return True

        return False

    def _repr(self):
        return "%s(%s, [%s])" % (
            type(self).__name__,
            self.get_type().__name__,
            ", ".join(repr(v) for v in self.__datas),
        )


class AnyValue(Template):
    @typecheck
    def __init__(self, type_: is_type):
        Template.__init__(self, type_)

    def _template_match(self, value):
        return True

    def _repr(self):
        return "%s(%s)" % (
            type(self).__name__,
            self.get_type().__name__,
        )


class Length(Template):
    @typecheck
    def __init__(
        self,
        parent: either(is_type, is_data),
        length: (either(
            int,
            tuple_of(int),
            list_of(either(
                int,
                tuple_of(int)))
            ))
    ):
        Template.__init__(self, parent)

        if not isinstance(length, list):
            length = [length]

        self.__length = [
            (v if isinstance(v, tuple) else(v, v))
            for v in length
        ]

        # check that 'length' contains valid values
        for lower, upper in self.__length:
            assert lower >= 0
            assert upper >= lower

    def _template_match(self, data):
        l = len(data)
        for lower, upper in self.__length:
            if lower <= l <= upper:
                return True
        return False

    def __initlist(self):
        for l, u in self.__length:
            if l == u:
                yield str(l)
            else:
                yield "(%s, %s)" % (l, u)

    def _repr(self):
        return "%s(%s, %s)" % (
            type(self).__name__,
            self.get_type().__name__,
            (
                "[%s]"
                %
                (", ".join(self.__initlist()))
                if len(self.__length) > 1
                else next(self.__initlist())
            )
        )


class Superset(Template):
    @typecheck
    def __init__(self, parent, datas: iterable):

        Template.__init__(self, parent)

        assert issubclass(self.get_type(), ListValue)
        assert not self.get_type().is_ordered()
        assert all(is_data(d) for d in datas)

        ct = self.get_type().get_content_type()
        self.__datas = tuple(store_data(d, ct) for d in datas)

    def _repr(self):
        return "%s(%s, [%s])" % (
            type(self).__name__,
            self.get_type().__name__,
            ", ".join(repr(v) for v in self.__datas),
        )

    def _template_match(self, value):
        missing = len(value) - len(self.__datas)
        if missing < 0:
            return False
        else:
            # TODO: do it in a more efficient way
            return self.get_type()(
                self.__datas + missing * (
                    AnyValue(self.get_type().get_content_type()),)
                ).match(value)

        return False


class Regex(Template):
    @typecheck
    def __init__(self, pattern: str, flags: optional(int) = 0):

        Template.__init__(self, str)

        self.__re = re.compile(pattern, flags)

    def _repr(self):
        flags = self.__re.flags
        flist = []
        for flagname in (
            'ASCII', 'DEBUG', 'IGNORECASE', 'LOCALE',
            'MULTILINE', 'DOTALL', 'VERBOSE', 'UNICODE'
        ):
            v = getattr(re, flagname)
            if v & flags:
                flags &= ~v
                flist.append("re." + flagname)
        if flags:
            flist.append(str(flags))

        return "%s(%s, %s)" % (
            type(self).__name__,
            repr(self.__re.pattern),
            "|".join(flist),
        )

    def _template_match(self, value):
        return bool(re.search(self.__re, value))


class All(Template):
    @typecheck
    def __init__(self, *templates):
        assert templates

        Template.__init__(self, get_type(templates[0]))  # FIXME: bof

        self.__templates = [self.store_data(t) for t in templates]

    def _repr(self):
        return "%s(%s)" % (
            type(self).__name__,
            ",".join(repr(t) for t in self.__templates),
        )

    # here we override _match since we need to match all templates
    #
    # FIXME: may have side effects in the HTML log module(we may have
    # multiple mismatch for the same value)
    def _match(self, value, mismatch_list):
        result = True
        for t in self.__templates:
            if not t.match(value, mismatch_list):
                result = False
        return result


class Any(Template):
    @typecheck
    def __init__(self, *templates):
        assert templates

        Template.__init__(self, get_type(templates[0]))  # FIXME: bof

        self.__templates = [self.store_data(t) for t in templates]

    def _repr(self):
        return "%s(%s)" % (
            type(self).__name__,
            ",".join(repr(t) for t in self.__templates),
        )

    def _template_match(self, value):
        return any(t.match(value) for t in self.__templates)


# #################### Part added from ts_coap plugin #################### #
class Not(Template):
    """
    Template class for Not
    """

    @typecheck
    def __init__(self, data: is_data):
        super().__init__(get_type(data))
        self.__data = store_data(data)

    @typecheck
    def _repr(self) -> str:
        return "%s(%s)" % (
            type(self).__name__,
            repr(self.__data),
        )

    @typecheck
    def _template_match(self, data: is_data) -> bool:
        return data not in self.__data
