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

"""
Analyzer module, defines all the needed tools to analyse a given dump file for
interoperability testing
"""

import glob
import inspect

from collections import OrderedDict
from importlib import import_module
from os import path
from ttproto.core.data import (Data, get_type, store_data,
                               DifferenceList, Value)
from ttproto.core.dissector import Frame
from ttproto.core.exceptions import Error
from ttproto.core.typecheck import *
from ttproto.core.lib.all import *
from ttproto.core.lib.ports.pcap import PcapReader


__all__ = [
    'Analyzer',
    'Verdict',
    'TestCase'
]


TESTCASES_SUBDIR = 'testcases'
TTPROTO_DIR = 'ttproto'
SEARCH_STRING = 'td_*.py'
ENTRY_MODULE = 'common'


@typecheck
def is_verdict(arg) -> bool:
    """
    Check if a parameter is a valid verdict.
    This function is used for the typechecker decorator.

    :return: True if a valid verdict, False if not
    :rtype: bool
    """
    return all((
        arg is not None,
        type(arg) == str,
        arg in Verdict.values()
    ))


class Verdict:
    """
    A class handling the verdict for an analysis

    Known verdict values are:
     - "none": No verdict set yet
     - "pass": The NUT fulfilled the test purpose
     - "inconc": The NUT did not fulfill the test purpose but did not display
                 bad behaviour
     - "fail": The NUT did not fulfill the test purpose and displayed a bad
               behaviour
     - "aborted": The test execution was aborted by the user
     - "error": A runtime error occured during the test

    At initialisation time, the verdict is set to None. Then it can be updated
    one or multiple times, either explicitely calling set_verdict() or
    implicitely if an unhandled exception is caught by the control module
    (error verdict) or if the user interrupts the test manually (aborted
    verdict).

    Each value listed above has precedence over the previous ones. This means
    that when a verdict is updated, the resulting verdict is changed only if
    the new verdict is worse than the previous one.
    """

    __values = ("none", "pass", "inconc", "fail", "aborted", "error")

    @typecheck
    def __init__(self, initial_value: optional(int) = None):
        self.__value = 0
        if initial_value is not None:
            self.update(initial_value)

    @typecheck
    def update(self, new_verdict: str, message: str = ''):
        """Update the verdict"""

        assert new_verdict in self.__values

        new_value = self.__values.index(new_verdict)
        if new_value > self.__value:
            self.__value = new_value

    @classmethod
    @typecheck
    def values(cls) -> tuple_of(str):
        """List the known verdict values"""
        return cls.__values

    @typecheck
    def get_value(self) -> str:
        """Get the value of the verdict"""
        return self.__values[self.__value]

    @typecheck
    def __str__(self) -> str:
        return self.__values[self.__value]


class TestCase:
    """
    A class handling a test case for an analysis
    """

    # Attribute to know if this TC is obsolete or not
    obsolete = False

    @typecheck
    def __init__(self, frame_list: list_of(Frame)):
        """
        Initialize a test case, the only thing that it needs for
        interoperability testing is a list of frame

        It will put the list of frames in it and then init the verdict

        :param frame_list: The list of frames to analyze
        :type frame_list: [Frame]
        """

        # Initialize its verdict instance and its list of frame
        self._verdict = Verdict()
        self._frames = frame_list

    @typecheck
    def match(self, sender, template, verdict: is_verdict = 'inconc', msg: str = '', *args):
        """
        Abstract function to match a packet value with a template

        :param verdict: The verdict to put if it matches
        :param msg: The message to associate with the verdict
        :param args: More arguments if needed into implementations
        :type verdict: str
        :type msg: str
        :type args: tuple
        """
        raise NotImplementedError

    @typecheck
    def next(self, optional: bool = False):
        """
        Switch to the next frame

        :param optional: If we have to get a next frame or not
        :type optional: bool
        """
        raise NotImplementedError

    def log(self, msg):
        """
        Log a message

        :param msg: The message to log
        :type msg: str
        """
        raise NotImplementedError

    @classmethod
    @typecheck
    def get_objective(self) -> str:
        """
        Get the objective of this test case

        :return: The objective of this test case
        :rtype: str
        """
        raise NotImplementedError

    @typecheck
    def pre_process(self) -> list_of(Frame):
        """
        Function for each TC to preprocess its list of frames

        :return: The list of ignored frames
        :rtype: [Frame]

        .. note:: Maybe it will be better to return the reason for the ignored?
                  Same, maybe it will be better to put this into the __init__
                  function so we don't have to call it implicitely and put
                  another method to get ignored frames?
        """
        raise NotImplementedError

    @typecheck
    def set_verdict(self, verdict: is_verdict, msg: str = ''):
        """
        Update the current verdict of the current test case

        :param verdict: The new verdict
        :param msg: The message to associate with the verdict
        :type verdict: str
        :type msg: str
        """
        self._verdict.update(verdict, msg)

        # TODO: Check that the log function will be used like this
        self.log("  [%s] %s" % (format(verdict, "^6s"), msg))

    def run(self) -> (str, list_of(int), str, list_of(Exception)):
        """
        Run the test case

        :return: A tuple with the informations about the running which are
                 - The verdict as a string
                 - The list of the review frames
                 - A string for extra informations
                 - A list of Exceptions that could have occured during the run
        :rtype: (str, [int], str, [Exception])

        .. note:: Maybe a decorator will be better to use because the TC run
                  method is implemented at the lowest level and we could need
                  to do some things before and after
        """
        raise NotImplementedError


class Analyzer:
    """
        Class for the analyzer tool
    """

    @typecheck
    def __init__(self, test_env: str):
        """
        Initialization function for the analyzer, just fetch the test env
        in which we will get the test description's implementation

        :param test_env: The test environment
        :type test_env: str

        :raises NotADirectoryError: If the test environemnt isn't found
        """

        # Check the test_env passed
        test_dir = path.join(
            TTPROTO_DIR,
            test_env,
            TESTCASES_SUBDIR
        )
        if not path.isdir(test_dir):
            raise NotADirectoryError(
                'The test environment wasn\'t found at %s'
                %
                test_dir
            )

        # Import test env common module
        # import_module('.'.join((TTPROTO_DIR, test_env, ENTRY_MODULE)))

        # LoggedObject.__init__(self)
        self.__test_env = test_env

    @typecheck
    def get_implemented_testcases(
        self,
        testcase_id: optional(str) = None,
        verbose: optional(bool) = False
    ) -> (list_of((str, str, str)), list_of((str, str, str))):
        """
        Imports test cases classes from TESTCASES_DIR named TD*

        :param testcase_id:

        :return: List of descriptions of test cases
                 1st list is the correct ones, the 2nd is the obsoletes one
                 Each element of the list is composed of:
                     -tc_identifier
                     -tc_objective
                     -tc_sourcecode
        :rtype: ([(str, str, str)], [(str, str, str)])

        :raises FileNotFoundError: If the test case is not found

        .. note::
                Assumptions v1:
                    - test cases are defined inside a file, each file contains
                      only one test case
                    - names of the file and class must match
                    - all test cases must be named td_*
                Assumptions v2:
                    - All test cases are contained into ttproto/[env]/testcases
                    - Filenames corresponds to the TC id in lower case
                    - Class names corresponds to the TC id
        .. todo:: Take a list as a param and return corresponding testcases
                  classes respecting the order.
        """

        # The return values
        testcases = []
        obsoletes = []

        # The search query
        search_query = path.join(
            TTPROTO_DIR,
            self.__test_env,
            TESTCASES_SUBDIR,
            SEARCH_STRING
        )

        # Find files named td_* or testcase_id if provided in TESTCASES_SUBDIR
        dir_list = glob.glob(search_query)

        # If none found
        if (len(dir_list) == 0):
            # self.log(EventNoTestCasesFound, search_query)
            raise FileNotFoundError(
                'No test case found using %s search query'
                %
                search_query
            )

        # Get all the module name by removing the extension '.py' and sort them
        modname_test_list = [
            path.basename(file)[:-3]
            for file in dir_list
            if path.isfile(file)
        ]
        modname_test_list.sort()

        # If a testcase_id is specified
        if testcase_id:

            # If it's found into the module names, single list element
            if testcase_id.lower() in modname_test_list:
                modname_test_list = [testcase_id]

            # If not found, raise an error
            else:
                # logger.log_event(EventFileNotFound(self, testcase_id))
                raise FileNotFoundError(
                    "Testcase : " + testcase_id + " couldn't be found"
                )

        # Import sorted list
        for modname in modname_test_list:

            # Build the module relative name
            mod_rel_name = '.'.join([
                TTPROTO_DIR,
                self.__test_env,
                TESTCASES_SUBDIR,
                modname.lower()
            ])

            # Note that the module is always lower case and the plugin (class)
            # is upper case (ETSI naming convention)
            tc = getattr(
                import_module(mod_rel_name),
                modname.upper()
            )

            # If verbose is asked, we provide the source code too
            more_info = inspect.getsource(tc) if verbose else ''

            # Check if obsolete or not
            if tc.obsolete:
                obsoletes.append((tc.__name__, tc.get_objective(), more_info))
            else:
                testcases.append((tc.__name__, tc.get_objective(), more_info))

        # Log a message if obsolete tcs are found
        # if obsoletes:
        #     self.log(EventObsoleteTCFound, obsoletes)

        # Return the final value
        return (testcases, obsoletes)

    @typecheck
    def analyse(
        self,
        filename: str,
        tc_id: str
    ) -> (str, str, list_of(int), str):
        """
        :param filename:
        :param tc_id:
        :return: tuple

        :raises FileNotFoundError: If the test env of the tc is not found
        :raises PcapError: If the provided file isn't a valid pcap file
        :raises ObsoleteTestCase: If the test case if obsolete

        example:
        [('TD_COAP_CORE_03', 'fail', [21, 22]), 'verdict description']

        NOTES:
         - allows multiple ocurrences of the testcase, returns as verdict:
                - fail: if at least one on the occurrences failed
                - inconc : if all ocurrences returned a inconv verdict
                - pass: all occurrences are inconc or at least one is PASS and
                        the rest is inconc
        """

        # Get the test case
        try:
            implemented_tcs, obsoletes = self.get_implemented_testcases(tc_id)
        except FileNotFoundError:
            raise FileNotFoundError(
                "Testcase : " + testcase_id + " couldn't be found"
            )

        # Check that we received only one
        assert len(implemented_tcs) + len(obsoletes) == 1

        # If the test case is obsolete
        if len(obsoletes) == 1:
            assert obsoletes[0][0] == tc_id
            raise ObsoleteTestCase(
                "Testcase : " + testcase_id + " is obsolete"
            )

        # Correct test case
        assert implemented_tcs[0][0] == tc_id
        modname = implemented_tcs[0][0]
        mod_real_name = '.'.join([
            TTPROTO_DIR,
            self.__test_env,
            TESTCASES_SUBDIR,
            modname.lower()
        ])

        # Load the test case class
        # Note that the module is always lower case and the plugin (class)
        # is upper case (ETSI naming convention)
        test_case_class = getattr(
            import_module(mod_real_name),
            modname.upper()
        )

        # Disable name resolution for performance improvment
        with Data.disable_name_resolution():

            # Get the list of frames from the file
            frames = Frame.create_list(PcapReader(filename))

            # Malformed frames are removed (can be done here or let to the TC)
            # FIXME: We do this HERE or into the TC IMPLEMENTATION ?
            malformed = [frame for frame in frames if frame.is_malformed()]
            print('#####')
            print('##### Malformed')
            print(malformed)
            print('#####')
            frames = [f for f in frames if f not in malformed]
            print('##### Frames in')
            print(frames)
            print('#####')

            # Initialize the TC with this list of frames
            test_case = test_case_class(frames)

            # Preprocess the list of frames which returns the list of ignored
            # FIXME: Maybe integrate the pre-processing into the constructor?
            ignored = test_case.pre_process()
            print('##### Ignored')
            print(ignored)
            print('#####')

            # Here we execute the test case and return the result
            test_case.run()
            print('##### Verdict given')
            print(test_case._verdict)
            print('#####')
            print('##### Review frames')
            print(test_case._failed_frames)
            print('#####')
            print('##### Text')
            print(test_case._text)
            print('#####')

            # Return the result
            return (tc_id, test_case._verdict.get_value(), test_case._failed_frames, test_case._text)
            # return (tc_id, v_txt, list(review_frames), extra_info)


class ObsoleteTestCase(Error):
    pass


if __name__ == "__main__":
    # print(Analyzer('tat_coap').get_implemented_testcases())
    # print(Analyzer('tat_coap').get_implemented_testcases('TD_COAP_CORE_24'))
    print(Analyzer('tat_coap').get_implemented_testcases(
        'TD_COAP_CORE_24', True
    ))
    # try:
    #     print(
    #         Analyzer('tat_coap').get_implemented_testcases('TD_COAP_CORE_42')
    #     )
    # except FileNotFoundError as e:
    #     print(e)
    # try:
    #     print(Analyzer('unknown').get_implemented_testcases())
    # except NotADirectoryError as e:
    #     print(e)
    # try:
    #     print(Analyzer('unknown').get_implemented_testcases('TD_COAP_CORE_42'))
    # except NotADirectoryError as e:
    #     print(e)
    # print(
    #     Analyzer('tat_coap').analyse(
    #         '/'.join((
    #             'tests',
    #             'test_files',
    #             'DissectorTests',
    #             'CoAP_plus_random_UDP_messages.pcap'
    #         )),
    #         'TD_COAP_CORE_01'
    #     )
    # )
    # print(
    #     Analyzer('tat_coap').analyse(
    #         '/'.join((
    #             'tests',
    #             'test_dumps',
    #             'TD_COAP_CORE_01_PASS.pcap'
    #         )),
    #         'TD_COAP_CORE_02'
    #     )
    # )
    tcs = Analyzer('tat_coap').get_implemented_testcases()
    for tc in tcs[0]:
        print(
            Analyzer('tat_coap').analyse(
                '/'.join((
                    'tests',
                    'test_dumps',
                    'TD_COAP_CORE_01_PASS.pcap'
                )),
                tc[0]
            )
        )
    pass
