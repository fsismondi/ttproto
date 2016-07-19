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
import traceback

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
TC_FILE_EXTENSION = '.py'
EVERY_TC_WILDCARD = 'td_*' + TC_FILE_EXTENSION


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
     - 'none': No verdict set yet
     - 'pass': The NUT fulfilled the test purpose
     - 'inconc': The NUT did not fulfill the test purpose but did not display
                 bad behaviour
     - 'fail': The NUT did not fulfill the test purpose and displayed a bad
               behaviour
     - 'aborted': The test execution was aborted by the user
     - 'error': A runtime error occured during the test

    At initialisation time, the verdict is set to None. Then it can be updated
    one or multiple times, either explicitely calling set_verdict() or
    implicitely if an unhandled exception is caught by the control module
    (error verdict) or if the user interrupts the test manually (aborted
    verdict).

    Each value listed above has precedence over the previous ones. This means
    that when a verdict is updated, the resulting verdict is changed only if
    the new verdict is worse than the previous one.
    """

    __values = ('none', 'pass', 'inconc', 'fail', 'aborted', 'error')

    @typecheck
    def __init__(self, initial_value: optional(int) = None):
        """
        Initialize the verdict value to 'none' or to the given value

        :param initial_value: The initial value to put the verdict on
        :type initial_value: optional(int)
        """
        self.__value = 0
        self.__message = ''
        if initial_value is not None:
            self.update(initial_value)

    @typecheck
    def update(self, new_verdict: str, message: str = ''):
        """
        Update the verdict

        :param new_verdict: The name of the new verdict value
        :param message: The message associated to it
        :type new_verdict: str
        :type message: str
        """
        assert new_verdict in self.__values

        new_value = self.__values.index(new_verdict)
        if new_value > self.__value:
            self.__value = new_value
            self.__message = message

    @classmethod
    @typecheck
    def values(cls) -> tuple_of(str):
        """
        List the known verdict values

        :return: The known verdict values
        :rtype: (str)
        """
        return cls.__values

    @typecheck
    def get_value(self) -> str:
        """
        Get the value of the verdict

        :return: The value of the verdict as a string
        :rtype: str
        """
        return self.__values[self.__value]

    @typecheck
    def get_message(self) -> str:
        """
        Get the last message update of this verdict

        :return: The last message update
        :rtype: str
        """
        return self.__message

    @typecheck
    def __str__(self) -> str:
        """
        Get the value of the verdict as string for printing it

        :return: The value of the verdict as a string
        :rtype: str
        """
        return self.__values[self.__value]


class TestCase:
    """
    A class handling a test case for an analysis
    """

    @typecheck
    def __init__(self, frame_list: list_of(Frame)):
        """
        Initialize a test case, the only thing that it needs for
        interoperability testing is a list of frame

        :param frame_list: The list of frames to analyze
        :type frame_list: [Frame]
        """
        raise NotImplementedError

    @typecheck
    def match(
        self,
        sender: either(str, type(None)),
        template: Value,
        verdict: optional(is_verdict) = 'inconc',
        msg: str = ''
    ) -> bool:
        """
        Abstract function to match the current frame value with a template

        :param sender: The sender of the packet
        :param template: The template to confront with current frame value
        :param verdict: The verdict to put if it matches
        :param msg: The message to associated with the verdict
        :type sender: str
        :type template: Value
        :type verdict: str
        :type msg: str

        :return: True if the current frame value matched the given template
                 False if not
        :rtype: bool
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

        :param msg: The message to log, can be of any type
        :type msg: object
        """
        raise NotImplementedError

    @classmethod
    @typecheck
    def get_test_purpose(self) -> str:
        """
        Get the purpose of this test case

        :return: The purpose of this test case
        :rtype: str
        """
        raise NotImplementedError

    @typecheck
    def pre_process(self) -> list_of((str, list_of(Frame))):
        """
        Function for each TC to preprocess its list of frames

        :return: The list of ignored frames associated to the ignoring reason
        :rtype: (str, [Frame])
        """
        # TODO re-engineer this, the pre process should return a list of the frames to be precessed and the ommited ones
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
        raise NotImplementedError

    @typecheck
    def run_test_case(self) -> (
        str,
        list_of(int),
        str,
        list_of((type, Exception, object))
    ):
        """
        Run the test case

        :return: A tuple with the informations about the test results which are
                 - The verdict as a string
                 - The list of the result important frames
                 - A string for extra informations
                 - A list of the exceptions' informations that occured
        :rtype: (str, [int], str, [(type, Exception, object)])

        .. todo:: Find the type of the traceback object, if we execute type
                  function on it, it just says <class 'traceback'> but the
                  isinstance function always return False
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

        :param test_env: The test environment which is the package name
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
                "The test environment wasn't found at %s"
                %
                test_dir
            )

        # LoggedObject.__init__(self)
        self.__test_env = test_env

    @typecheck
    def __fetch_from_pathname(self, testcases: list_of(type), search: str):
        """
        Fetch test cases from the test suite plugin

        :param testcases: List in which we will add the test cases
        :param search: The research query, can be a single TC or the wildcard
                       to select all the test cases
        :type testcases: [type]
        :type search: str
        """

        # Build the search query
        search_query = path.join(
            TTPROTO_DIR,
            self.__test_env,
            TESTCASES_SUBDIR,
            search
        )

        # Fetch files using the search query
        result = glob.glob(search_query)

        # If no test case found
        if len(result) == 0:
            raise FileNotFoundError(
                'No test case found using "%s" search query' % search_query
            )

        # If the search query is the wildcard, sort the list
        elif search == EVERY_TC_WILDCARD:
            result.sort()

        # For every file found
        for filepath in result:

            # Get the name of the file
            filename = path.basename(filepath)

            # Get the name of the module
            modname = filename[:(-1 * len(TC_FILE_EXTENSION))]

            # Build the module relative name
            mod_rel_name = '.'.join([
                TTPROTO_DIR,
                self.__test_env,
                TESTCASES_SUBDIR,
                modname
            ])

            # Note that the module is always lower case and the plugin (class)
            # is upper case (ETSI naming convention)
            tc_class = getattr(
                import_module(mod_rel_name),
                modname.upper()
            )
            testcases.append(tc_class)

    @typecheck
    def import_test_cases(
        self,
        testcases: optional(list_of(str)) = None
    ) -> list:
        """
        Imports test cases classes from TESTCASES_DIR

        :param testcases: The wanted test cases as a list of string
        :type testcase_id: optional([str])

        :return: List of test cases class in the same order than the param list
        :rtype: [TestCase]

        :raises FileNotFoundError: If no test case was found

        .. note:: Assumptions are the following:
                    - Test cases are defined inside a file, each file contains
                      only one test case
                    - All test cases must be named td_*
                    - All test cases are contained into ttproto/[env]/testcases
                    - Filenames corresponds to the TC id in lower case
                    - Class names corresponds to the TC id
        """

        # The return values
        tc_fetched = []

        # If no TCs provided, fetch all the test cases found
        if not testcases:
            self.__fetch_from_pathname(tc_fetched, EVERY_TC_WILDCARD)

        # If testcases list are provided, fetch those
        else:

            # For every test case given
            for test_case_name in testcases:
                tc_name_query = test_case_name.lower() + TC_FILE_EXTENSION
                self.__fetch_from_pathname(tc_fetched, tc_name_query)

        # Return the test cases classes
        return tc_fetched

    @typecheck
    def get_implemented_testcases(
        self,
        testcases: optional(list_of(str)) = None,
        verbose: bool = False
    ) -> list_of((str, str, str)):
        """
        Get more informations about the test cases

        :param testcases: A list of test cases to get their informations
        :param verbose: True if we want the TC implementation code
        :type testcase_id: optional([str])
        :type verbose: bool

        :raises FileNotFoundError: If one of the test case is not found

        :return: List of descriptions of test cases composed of:
                    -tc_identifier
                    -tc_objective
                    -tc_sourcecode
        :rtype: [(str, str, str)]
        """

        # The return value
        ret = []

        # Get the tc classes
        tc_classes = self.import_test_cases(testcases)

        # Add the infos of each of them to the return value
        for tc in tc_classes:

            # If verbose is asked, we provide the source code too
            more_info = '' if not verbose else inspect.getsource(tc)

            # Add the tuple to the return value
            ret.append((tc.__name__, tc.get_test_purpose(), more_info))

        # Return the list of tuples
        return ret

    @typecheck
    def analyse(
        self,
        filename: str,
        tc_id: str
    ) -> (str, str, list_of(int), str, str):
        """
        Analyse a dump file associated to a test case

        :param filename: The name of the file to analyse
        :param tc_id: The unique id of the test case to confront the given file
        :type filename: str
        :type tc_id: str

        :return: A tuple with the informations about the analyse results:
                 - The id of the test case
                 - The verdict as a string
                 - The list of the result important frames
                 - A string for extra informations
                 - A string representing the exceptions that could have occured
        :rtype: (str, str, [int], str, str)

        :raises FileNotFoundError: If the test env of the tc is not found
        :raises PcapError: If the provided file isn't a valid pcap file
        :raises ObsoleteTestCase: If the test case if obsolete

        .. example::
            ('TD_COAP_CORE_03', 'fail', [21, 22], 'verdict description', '')

        .. note::
            - Allows multiple ocurrences of the testcase, returns as verdict:
                - fail: if at least one on the occurrences failed
                - inconc: if all ocurrences returned a inconv verdict
                - pass: all occurrences are inconc or at least one is PASS and
                        the rest is inconc
        """

        # Get the test case class
        test_case_class = self.import_test_cases([tc_id])
        assert len(test_case_class) == 1
        test_case_class = test_case_class[0]

        # Disable name resolution for performance improvment
        with Data.disable_name_resolution():

            # Get the list of frames from the file
            frames = Frame.create_list(PcapReader(filename))

            # Initialize the TC with this list of frames
            test_case = test_case_class(frames)

            # Preprocess the list of frames which returns the list of ignored
            # TODO pre_process MUST return two objects: a list of conversations
            #      related to the TC, and the ignored ones
            ignored = test_case.pre_process()

            # print('##### Ignored')
            # print(ignored)
            # print('#####')

            # Here we execute the test case and return the result
            verdict, rev_frames, extra, exceptions = test_case.run_test_case()
            # print('##### Verdict given')
            # print(verdict)
            # print('#####')
            # print('##### Review frames')
            # print(rev_frames)
            # print('#####')
            # print('##### Text')
            # print(extra)
            # print('#####')
            # print('##### Exceptions')
            # print(exceptions)
            # print('#####')

            # Return the result
            return (tc_id, verdict, rev_frames, extra, 'exceptions')


class ObsoleteTestCase(Error):
    pass


if __name__ == "__main__":
    # print(Analyzer('tat_coap').import_test_cases())
    # print(Analyzer('tat_6tisch').import_test_cases())
    # print(Analyzer('tat_coap').import_test_cases(['TD_COAP_CORE_24']))
    # print(Analyzer('tat_coap').import_test_cases([
    #     'TD_COAP_CORE_01',
    #     'TD_COAP_CORE_02'
    # ]))
    # print(Analyzer('tat_coap').get_implemented_testcases())
    # print(Analyzer('tat_6tisch').get_implemented_testcases())
    # print(Analyzer('tat_coap').get_implemented_testcases(['TD_COAP_CORE_24']))
    # print(Analyzer('tat_coap').get_implemented_testcases([
    #     'TD_COAP_CORE_01',
    #     'TD_COAP_CORE_05',
    #     'TD_COAP_CORE_09'
    # ]))
    # print(Analyzer('tat_coap').get_implemented_testcases(
    #     ['TD_COAP_CORE_24'], True
    # ))
    # print(Analyzer('tat_coap').get_implemented_testcases([
    #     'TD_COAP_CORE_01',
    #     'TD_COAP_CORE_05',
    #     'TD_COAP_CORE_09'
    # ], True))
    # try:
    #     print(
    #         Analyzer('tat_coap').get_implemented_testcases(['TD_COAP_CORE_42'])
    #     )
    # except FileNotFoundError as e:
    #     print(e)
    # try:
    #     print(Analyzer('unknown').get_implemented_testcases())
    # except NotADirectoryError as e:
    #     print(e)
    # try:
    #     print(Analyzer('unknown').get_implemented_testcases(['TD_COAP_CORE_42']))
    # except NotADirectoryError as e:
    #     print(e)
    # print(
    #     Analyzer('tat_coap').analyse(
    #         '/'.join((
    #             'tests',
    #             'test_dumps',
    #             '_'.join((
    #                 'TD',
    #                 'COAP',
    #                 'CORE',
    #                 '07',
    #                 'FAIL',
    #                 'No',
    #                 'CoAPOptionContentFormat',
    #                 'plus',
    #                 'random',
    #                 'UDP',
    #                 'messages.pcap'
    #             ))
    #         )),
    #         'TD_COAP_CORE_01'
    #     )
    # )
    # try:
    #     print(
    #         Analyzer('tat_6tisch').get_implemented_testcases()
    #     )
    # except FileNotFoundError as e:
    #     print(e)
    # try:
    #     print(Analyzer('tat_6tisch').get_implemented_testcases())
    # except NotADirectoryError as e:
    #     print(e)
    # try:
    #     print(Analyzer('tat_6tisch').get_implemented_testcases())
    # except NotADirectoryError as e:
    #     print(e)
    print(
        Analyzer('tat_coap').analyse(
            '/'.join((
                'tests',
                'test_dumps',
                '_'.join((
                    'TD',
                    'COAP',
                    'CORE',
                    '07',
                    'FAIL',
                    'No',
                    'CoAPOptionContentFormat',
                    'plus',
                    'random',
                    'UDP',
                    'messages.pcap'
                ))
            )),
            'TD_COAP_CORE_01'
        )
    )
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
    # tcs = Analyzer('tat_coap').get_implemented_testcases()
    # for tc in tcs:
    #     print('#####################  ' + tc[0] + '  #####################')
    #     try:
    #         print(
    #             Analyzer('tat_coap').analyse(
    #                 '/'.join((
    #                     'tests',
    #                     'test_dumps',
    #                     tc[0] + '_PASS.pcap'
    #                 )),
    #                 tc[0]
    #             )
    #         )
    #     except FileNotFoundError:
    #         print(tc[0] + " doesn't have a dump file associated to it")
    #     print('############################################################')
    #     print('')
    pass
