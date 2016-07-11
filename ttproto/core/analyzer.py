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

    # Attribute to know if this TC is obsolete or not
    obsolete = False

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


    # TODO why exceptions as string? maybe better handling directly the objects at this level, we flatten to
    # TODO string if needed to be passed trough the web API
    @typecheck
    def run_test_case(self) -> (str, list_of(int), str, str):
        """
        Run the test case

        :return: A tuple with the informations about the test results which are
                 - The verdict as a string
                 - The list of the result important frames
                 - A string for extra informations
                 - A string representing the exceptions that could have occured
        :rtype: (str, [int], str, str)
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
                'The test environment wasn\'t found at %s'
                %
                test_dir
            )

        # LoggedObject.__init__(self)
        self.__test_env = test_env

    @typecheck
    def PATCH_get_implemented_testcases(
        self,
        testcase_id: optional(str) = None,
        verbose: optional(bool) = False
    ):
        """
        Imports test cases classes from TESTCASES_DIR named td_*

        :param testcase_id: The id of the test case if only one is asked
        :param verbose: True if we want the TC implementation code
        :type testcase_id: optional(str)
        :type verbose: bool

        :return: List of descriptions of test cases
                 1st list is the correct ones, the 2nd is the obsoletes one
                 Each element of the list is composed of:
                     -tc_identifier
                     -tc_objective
                     -tc_sourcecode
        # TODO this was patched for the case of 6tisch test cases, we need a common approach for every protocol
        # TODO is it interesting enough to handle obsoletes testcases??
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

        # TODO take a list as a param and return corresponding testcases classes respecting the order.
        SEARCH_STRING = 'td*.py'
        tc_plugins = {}
        testcases = []
        obsoletes = []
        TESTCASES_SUBDIR = "ttproto/tat_6tisch/testcases"
        import os, sys
        prv_wd = os.getcwd()
        os.chdir(prv_wd + '/' + TESTCASES_SUBDIR)

        #  find files named "TD*" or testcase_id (if provided) in TESTCASES_DIR
        dir_list = glob.glob(SEARCH_STRING)
        modname_test_list = [path.basename(f)[:-3] for f in dir_list if path.isfile(f)]
        modname_test_list.sort()

        if testcase_id:
            if testcase_id.lower() in modname_test_list:
                modname_test_list = [testcase_id]

                # filename not found in dir
            else:
                # move back to the previously dir
                os.chdir(prv_wd)
                raise FileNotFoundError("Testcase : " + testcase_id + " couldn't be found")

        # import sorted list
        for modname in modname_test_list:
            # note that the module is always lower case and the plugin (class) is upper case (ETSI naming convention)
            tc_plugins[modname] = getattr(import_module(modname.lower()), modname.upper())
            if tc_plugins[modname].obsolete:
                obsoletes.append(tc_plugins[modname])
            else:
                testcases.append(tc_plugins[modname])

        # move back to the previously dir
        os.chdir(prv_wd)

        assert all(isinstance(t, type) and issubclass(t, TestCase) for t in testcases)

        if obsoletes:
            sys.stderr.write("%d obsolete testcases:\n" % len(obsoletes))
            for tc_type in obsoletes:
                sys.stderr.write("\t%s\n" % tc_type.__name__)

        return testcases, obsoletes

    @typecheck
    def get_implemented_testcases(
            self,
            testcase_id: optional(str) = None,
            verbose: optional(bool) = False
    ) -> (list_of((str, str, str)), list_of((str, str, str))):
        """
        Imports test cases classes from TESTCASES_DIR named td_*

        :param testcase_id: The id of the test case if only one is asked
        :param verbose: True if we want the TC implementation code
        :type testcase_id: optional(str)
        :type verbose: bool

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
            more_info = '' if not verbose else inspect.getsource(tc)

            # The tuple to add
            tc_tuple = (tc.__name__, tc.get_test_purpose(), more_info)

            # Check if obsolete or not
            if tc.obsolete:
                obsoletes.append(tc_tuple)
            else:
                testcases.append(tc_tuple)

        # Log a message if obsolete tcs are found
        # if obsoletes:
        #     self.log(EventObsoleteTCFound, obsoletes)

        # Return the final value
        return testcases, obsoletes

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

        # # Get the test case
        # try:
        #     implemented_tcs, obsoletes = self.get_implemented_testcases(tc_id)
        # except FileNotFoundError:
        #     raise FileNotFoundError(
        #         "Testcase : " + tc_id + " couldn't be found"
        #     )
        #
        # # Check that we received only one
        # assert len(implemented_tcs) + len(obsoletes) == 1
        #
        # # If the test case is obsolete
        # if len(obsoletes) == 1:
        #     assert obsoletes[0][0] == tc_id
        #     raise ObsoleteTestCase(
        #         "Testcase : " + tc_id + " is obsolete"
        #     )
        #
        # # Correct test case
        # assert implemented_tcs[0][0] == tc_id
        # modname = implemented_tcs[0][0]
        # mod_real_name = '.'.join([
        #     TTPROTO_DIR,
        #     self.__test_env,
        #     TESTCASES_SUBDIR,
        #     modname.lower()
        # ])

        # TODO Napoun here (followin three lines) we have the same snippet in two places, redundant code,
        # TODO let's use the appraoch I was using before with two separete functions, one for import,
        # TODO the other, get_tc_info for getting infos from TCs,
        # TODO get_tc_info MUST use import_test_cases

        # # Load the test case class
        # # Note that the module is always lower case and the plugin (class)
        # # is upper case (ETSI naming convention)
        # test_case_class = getattr(
        #     import_module(mod_real_name),
        #     modname.upper()
        # )

        # self.PATCH_get_implemented_testcases[0][0] is class SixtischTestcase
        test_case_class, _ = self.PATCH_get_implemented_testcases(tc_id)
        test_case_class = test_case_class[0]

        # Disable name resolution for performance improvment
        with Data.disable_name_resolution():

            # Get the list of frames from the file
            frames = Frame.create_list(PcapReader(filename))

            # Initialize the TC with this list of frames
            test_case = test_case_class(frames)

            # Preprocess the list of frames which returns the list of ignored
            # TODO pre_process MUST return two objects: a list of conversations related to the TC, and the ignored ones
            #ignored = test_case.pre_process()
            # print('##### Ignored')
            # print(ignored)
            # print('#####')

            # Here we execute the test case and return the result
            res = test_case.run_test_case()
            # print('##### Verdict given')
            # print(res[0])
            # print('#####')
            # print('##### Review frames')
            # print(res[1])
            # print('#####')
            # print('##### Text')
            # print(res[2])
            # print('#####')
            # print('##### Exceptions')
            # print(res[3])
            # print('#####')

            # Return the result
            return (tc_id, res[0], res[1], res[2], res[3])


class ObsoleteTestCase(Error):
    pass


if __name__ == "__main__":
    # print(Analyzer('tat_coap').get_implemented_testcases())
    # print(Analyzer('tat_coap').get_implemented_testcases('TD_COAP_CORE_24'))
    # print(Analyzer('tat_coap').get_implemented_testcases(
    #     'TD_COAP_CORE_24', True
    # ))
    try:
        print(
            Analyzer('tat_6tisch').get_implemented_testcases()
        )
    except FileNotFoundError as e:
        print(e)
    try:
        print(Analyzer('tat_6tisch').get_implemented_testcases())
    except NotADirectoryError as e:
        print(e)
    try:
        print(Analyzer('tat_6tisch').get_implemented_testcases())
    except NotADirectoryError as e:
        print(e)
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
    # for tc in tcs[0]:
    #     print('#####################  ' + tc[0] + '  #####################')
    #     print(
    #         Analyzer('tat_coap').analyse(
    #             '/'.join((
    #                 'tests',
    #                 'test_dumps',
    #                 'TD_COAP_CORE_01_PASS.pcap'
    #             )),
    #             tc[0]
    #         )
    #     )
    #     print('############################################################')
    #     print('')
    pass
