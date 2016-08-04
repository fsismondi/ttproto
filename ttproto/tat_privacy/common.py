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

from ttproto.core.analyzer import TestCase, is_protocol, Node
from ttproto.core.templates import All, Not, Any, Length
from ttproto.core.typecheck import *
from ttproto.core.lib.all import *
from urllib import parse


class CoAPAnalysis(TestCase):
    """
    The test case extension representing a Sixlowpan test case
    """

    @classmethod
    @typecheck
    def get_test_purpose(cls) -> str:
        """
        Get the purpose of this test case

        :return: The purpose of this test case
        :rtype: str
        """
        if cls.__doc__:
            save = False
            for line in cls.__doc__.splitlines():
                if line.startswith('Objective'):
                    ret = line.split('*')[1]
                    save = True
                elif line.startswith('Configuration'):
                    return ' '.join(ret.split())
                elif save:
                    ret += line
        return ''
