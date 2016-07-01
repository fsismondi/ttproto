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

import itertools

from ttproto.core.data import Template, Mismatch
from ttproto.core.lib.inet.all import *


# #################### CoAP specific Templates #########################

class Opt(Template):
    """
    A template to match a list of options in the right order

    Options are matched by type(eg: CoAPOptionToken, CoAPOptionContentFormat,
    ...).

    All types that are not present in the template will be ignored at
    matching time.

    If a type occurs at least once in the template, then all options of
    this type in the value must be present and match the corresponding
    options in the template, and in the same order.
    """

    def __init__(self, *opts, superset=False):
        super().__init__(CoAPOptionList)

        self.__opts = {}
        self.__superset = superset
        for o in opts:

            t = get_type(o)
            assert issubclass(t, CoAPOption)

            try:
                self.__opts[t].append(store_data(o))
            except KeyError:
                self.__opts[t] = [o]

    def opts(self, type):
        lst = self.__opts.get(type)
        return iter(lst if lst else())

    def _repr(self):
        return "%s(%s%s)" % (
            type(self).__name__,
            ", ".join(
                (", ".join(repr(v) for v in l))
                for l in self.__opts.values()
            ),
            (", superset=True" if self.__superset else "")
        )

    def _match(self, value, mismatch_list):
        end = []

        result = True
        for typ, lst in self.__opts.items():
            ok = True
            for val, tp in itertools.zip_longest(
                    # select all values matching this type
                    filter((lambda x: isinstance(x, typ)), value),
                    lst, fillvalue=end):
                if val is end:
                    # more templates than values
                    ok = False
                    break
                if tp is end:
                    # more values than templates
                    if not self.__superset:
                        # superset not allowed
                        ok = False
                    break

                if val not in tp:
                    ok = False
            if not ok:
                result = False
                if mismatch_list is not None:
                    mismatch_list.append(CoAPOptMismatch(value, self, typ))
        return result


class NoOpt(Template):
    """A template to check that some options are not present"""

    def __init__(self, *opts):
        super().__init__(CoAPOptionList)

        self.__opts = [store_data(o) for o in opts]

    def _repr(self):
        return "%s(%s)" % (
            type(self).__name__,
            ", ".join(repr(o) for o in self.__opts),
        )

    def _match(self, value, mismatch_list):
        for t in self.__opts:
            for v in value:
                if v in t:
                    if mismatch_list is not None:
                        mismatch_list.append(
                            CoAPNoOptMismatch(value, self, v, t)
                        )
                    return False
        return True


# #################### CoAP specific Mismatch #########################
class CoAPNoOptMismatch(Mismatch):
    def __init__(self, value, pattern, opt_v, opt_p):
        super().__init__(value, pattern)
        self.opt_value = opt_v
        self.opt_pattern = opt_p

    def describe_value(self, describe_func=None):
        return str(self.opt_value)

    def describe_expected(self, describe_func=None):
        return "%s  not present" % self.opt_pattern


class CoAPOptMismatch(Mismatch):
    def __init__(self, value, pattern, opt_type):
        super().__init__(value, pattern)
        self.opt_type = opt_type

    def describe_value(self, describe_func=None):
        return ", ".join(
            str(o) for o in self.value
            if type(o) is self.opt_type
        )

    def describe_expected(self, describe_func=None):
        return ", ".join(str(o) for o in self.pattern.opts(self.opt_type))
