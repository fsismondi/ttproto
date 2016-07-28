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

import os
import sys

from unittest import main, TestLoader, TestResult
from importlib import import_module

TEST_DIR = 'tests'


if __name__ == '__main__':

    sys.stderr.write('################# BEGINNING OF TESTS #################')

    # NOTE: In all the following, write the output on stderr because stdout is
    #       redirected for webservers. By the way, it seems that even the
    #       sys.stderr.write into the tested modules break the redirected pipe.

    # # FIRST WAY

    # # Load all the test cases from the discover method
    # loader = TestLoader()
    # ttproto_test_suite = loader.discover(TEST_DIR)

    # # Run all the test cases providing the result storage
    # result = TestResult()
    # ttproto_test_suite.run(result)

    # # Display results
    # sys.stderr.write("\n\n")
    # sys.stderr.write('################## ERRORS ##################')
    # for err in result.errors:
    #     sys.stderr.write(err[0].__name__ + ': ' + err[1])

    # sys.stderr.write("\n\n")
    # sys.stderr.write('################## FAILURES ##################')
    # for fail in result.failures:
    #     sys.stderr.write(fail[0].__name__ + ': ' + fail[1])

    # sys.stderr.write("\n\n")
    # sys.stderr.write('################## SKIPPED ##################')
    # for skip in result.skipped:
    #     sys.stderr.write(skip[0].__name__ + ': ' + skip[1])

    # SECOND WAY
    # Seek recursively every module into tests directory
    for root, subdirs, files in os.walk(TEST_DIR):

        # Execute every test file found
        for filename in files:
            if all((
                filename.startswith('test'),
                filename.endswith('.py'),
                filename != 'tests.py'  # We don't check old test files
            )):
                test_name = os.path.splitext(filename)[0].upper()
                mod_name = root.replace('/', '.') + '.' + test_name.lower()

                sys.stderr.write("\n\n")
                sys.stderr.write('############ ' + test_name + ' ############')
                sys.stderr.write("\n")

                main(module=mod_name, exit=False)

                sys.stderr.write('###########################################')
