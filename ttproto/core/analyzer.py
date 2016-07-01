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

import glob
import inspect

from os import path
from importlib import import_module
from ttproto.core import logger
from ttproto.core.data import Data
from ttproto.core.dissector import Frame
from ttproto.core.logger import LoggedObject, LogEventClass
from ttproto.core.typecheck import *
from ttproto.core.lib.ports.pcap import PcapReader
from ttproto.tat_coap.proto_specific import (CoAPTestcase, CoAPTracker,
                                             group_conversations_by_pair)

# TODO: Remove this and use ttproto core and generic class instead
TestCase = CoAPTestcase
Tracker = CoAPTracker


__all__ = [
    'Analyzer'
]


TESTCASES_SUBDIR = 'testcases'
TTPROTO_DIR = 'ttproto'
SEARCH_STRING = 'td_*.py'


# class Analyzer(LoggedObject):
class Analyzer:
    """
        Class for the analyzer tool
    """

    verdicts = None, "inconc", "pass", "fail", "error"

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

            # Check the tc
            assert isinstance(tc, type) and issubclass(tc, TestCase)

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
        tc_id: str,
        urifilter: optional(str) = None,
        exceptions: optional(list) = None,
        profile: str = 'client',
        verbose: bool = False
    ) -> (str, str, list_of(int), str):
        """
        :param filename:
        :param urifilter:
        :param exceptions:
        :param tc_di:
        :param profile:
        :param verbose: boolean, if true method returns verdict description
                        (which may be very verbose)
        :return: tuple

        :raises FileNotFoundError: If the test env of the tc is not found
        :raises PcapError: If the provided file isn't a valid pcap file

        example:
        [('TD_COAP_CORE_03', 'fail', [21, 22]), 'verdict description']

        NOTES:
         - allows multiple ocurrences of the testcase, returns as verdict:
                - fail: if at least one on the occurrences failed
                - inconc : if all ocurrences returned a inconv verdict
                - pass: all occurrences are inconc or at least one is PASS and
                        the rest is inconc
        """

        # Get all the implemented test cases
        try:
            implemented_tcs, _ = self.get_implemented_testcases(tc_id)
        except FileNotFoundError:
            # self.log(EventFileNotFound, testcase_id)
            raise FileNotFoundError(
                "Testcase : " + testcase_id + " couldn't be found"
            )

        # Import test cases
        test_cases = []

        # Build the module relative name
        for tc in implemented_tcs:
            modname = tc[0]
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

            # In function of the current profile ('client' or 'reverse-proxy')
            # TODO: This should be generic and put as core.Config class
            if tc.reverse_proxy == (profile == 'reverse-proxy'):
                test_cases.append(tc)

        # In function of the current profile ('client' or 'reverse-proxy')
        # TODO: This should be generic and put as core.Config class
        # test_cases = [
        #     t for t in implemented_tcs
        #     if eval(t[0]).reverse_proxy == (profile == 'reverse-proxy')
        # ]

        # Check if there's only one test case to confront the pcap file
        force = len(test_cases) == 1

        # Disable name resolution for performance improvment
        with Data.disable_name_resolution():

            # Get the list of frames from the file
            frames = Frame.create_list(PcapReader(filename))

            # Malformed frames
            malformed = [frame for frame in frames if frame.is_malformed()]

            # Create the tracker from the frames
            # TODO: This part needs to be generic
            #
            # It consists into taking frames, grouping them by conversations
            # and filtering interessant (coap) frames from those ignored
            # This part is REALLY specific for CoAP
            tracker = Tracker(frames)
            conversations = tracker.conversations
            ignored = tracker.ignored_frames

            # Return results
            # results = []

            # Get the conversations by pair
            # TODO: This part is also very specific to CoAP
            conversations_by_pair = group_conversations_by_pair(conversations)

            # Parse the conversations grouped by pair
            # pair => A tuple (client, server)
            # conversations => A list of corresponding conversations put by
            #                  pair and in temporal order
            for pair, conversations in conversations_by_pair.items():

                # The results also by pair
                pair_results = []

                # For every test cases found (most of the time, there will be
                # only one)
                for tc_type in test_cases:

                    # Results for each tc
                    tc_results = []

                    # We run the testcase for each conversation, meaning that
                    # one type of TC can have more than one result!
                    for tr in conversations:

                        # Create the CoAPTestCase object from parameters
                        tc = tc_type(tr, urifilter, force)

                        # If there's a result
                        if tc.verdict:
                            tc_results.append(tc)

                            # If exception, add it to the function parameter
                            if all((
                                hasattr(tc, "exception"),
                                exceptions is not None
                            )):
                                exceptions.append(tc)

                    # Append the results of each test case confronted to this
                    # conversation pair
                    pair_results.append(tc_results)

            # Get only the results of the test case that we requested
            # You can look upper and see that we loop on ALL the test cases,
            # whereas here we only loop on the requested ones (can be many)
            # for tc_type, tc_results in filter(
            #     lambda x: tc_id in x[0].__name__,
            #     zip(test_cases, pair_results)
            # ):

            (tc_type, tc_results) = filter(
                lambda x: tc_id == x[0].__name,  # Take only the requested tc
                zip(test_cases, pair_results)  # Parse the 2 lists in parallel
            )

            # Prepare the review frames list
            review_frames = []

            # Current verdict (inconc)
            v = 0

            # For every results
            for tc in tc_results:

                # All the failed frames for a TC, even if they are from
                # different conversations!
                review_frames = tc.failed_frames

                # Get the new verdict and update current one if the new has
                # higher priority
                new_v = self.verdicts.index(tc.verdict)
                if new_v > v:
                    v = new_v

            # Get the text value of the verdict
            v_txt = self.verdicts[v]
            if v_txt is None:
                v_txt = "none"

            # Compute the extra informations
            extra_info = tc.text if verbose else ''

            # Return the result
            return (type(tc).__name__, v_txt, list(review_frames), extra_info)

            # TODO clean list(review_frames)  tc.review_frames_log,
            # tc.review_frames_log in module proto_specific

            # return results


class EventNoTestCasesFoundForAnalysis(metaclass=LogEventClass):
    fields = (
        ('analyzer', Analyzer),
        ('test_case', str),
        ('test_env', str),
        ('profile', str)
    )

    def summary(self):
        return (
            "%s: No TC %s found in %s test env and with %s profile"
            %
            (self[0].__name__, self[1], self[2], self[3])
        )


class EventNoTestCasesFound(metaclass=LogEventClass):
    fields = (
        ('analyzer', Analyzer),
        ('search_query', str)
    )

    def summary(self):
        return (
            "%s: Non TC found with %s query" % (self[0].__name__, self[1])
        )


class EventObsoleteTCFound(metaclass=LogEventClass):
    fields = (
        ('analyzer', Analyzer),
        ('obsoletes', list)  # Class list
    )

    def summary(self):

        # Build the string representation of obsolete tc class list
        first = True
        class_str_repr = '['
        for obs_class in self[1]:
            assert type(obs_class) == type
            if not first:
                class_str_repr += ', '
            class_str_repr += obs_class.__name__
            first = False
        class_str_repr += ']'

        # Return the warning to be logged
        return (
            "%s: %d obsolete testcases found:\n%s"
            %
            (self[0].__name__, len(self[1]), class_str_repr)
        )


class EventFileNotFound(metaclass=LogEventClass):
    fields = (
        ('analyzer', Analyzer),
        ('filename', str)
    )

    def summary(self):
        return (
            "%s: Testcase %s couldn't be found" % (self[0].__name__, self[1])
        )


if __name__ == "__main__":
    print(Analyzer('tat_coap').get_implemented_testcases())
    print(Analyzer('tat_coap').get_implemented_testcases('TD_COAP_CORE_24'))
    try:
        print(Analyzer('tat_coap').get_implemented_testcases('TD_COAP_CORE_42'))
    except FileNotFoundError as e:
        print(e)
    try:
        print(Analyzer('unknown').get_implemented_testcases())
    except NotADirectoryError as e:
        print(e)
    try:
        print(Analyzer('unknown').get_implemented_testcases('TD_COAP_CORE_42'))
    except NotADirectoryError as e:
        print(e)
    # print(
    #     Analyzer('tat_coap').analyse(
    #         'tests/test_dumps/TD_COAP_CORE_01_PASS.pcap',
    #         'TD_COAP_CORE_01'
    #     )
    # )
    pass
