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
import itertools
import sys
import traceback

from os import path
from collections import OrderedDict
from importlib import import_module

from ttproto.core.data import (Data, get_type, store_data, DifferenceList,
                               Value)
from ttproto.core.dissector import Frame, Capture, ReaderError, is_protocol
from ttproto.core.exceptions import Error
from ttproto.core.typecheck import *
from ttproto.core.lib.all import *


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


@typecheck
def is_traceback(arg) -> bool:
    """
    Check if a parameter is a valid traceback object.
    This function is used for the typechecker decorator.

    :return: True if a valid traceback, False if not
    :rtype: bool

    .. note:: Didn't find a better way to check this, isinstance or type
              seems to not work
    """
    return all((
        arg is not None,
        hasattr(arg, '__class__'),
        hasattr(arg.__class__, '__name__'),
        isinstance(arg.__class__.__name__, str),
        arg.__class__.__name__ == 'traceback'
    ))


@typecheck
def is_tc_subclass(arg) -> bool:
    """
    Check if a parameter is a valid traceback object.
    This function is used for the typechecker decorator.

    :return: True if a valid traceback, False if not
    :rtype: bool

    .. note:: Didn't find a better way to check this, isinstance or type
              seems to not work
    """
    return all((
        arg is not None,
        type(arg) == type,
        issubclass(arg, TestCase)
    ))


class FilterError(Error):
    pass


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


class Node(object):
    """
    The Node object which represents an node communicating with another one
    on a conversation. It can be a node, a client/server, an host, etc.

    It will have a name (ex: client, node1, iut2, border_router) and an
    associated value, like an IP or a MAC address for example.
    """

    @typecheck
    def __init__(self, name: str, value: anything):
        """
        Create an node object

        :param name: The name of this node
        :param value: The value associated to this node
        :type name: str
        :type value: anything
        """
        self._name = name
        self._value = value

    def __repr__(self):
        """
        Get the string representation of this node

        :return: String representation of this node
        :rtype: str
        """
        return "Node named %s valued as %s" % (self._name, self._value)

    @property
    def name(self):
        """
        Function to get the name

        :return: The name
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, value):
        raise AttributeError('Setting name attribute is not allowed')

    @property
    def value(self):
        """
        Function to get the value

        :return: The value
        :rtype: anything
        """
        return self._value

    @value.setter
    def value(self, value):
        raise AttributeError('Setting value attribute is not allowed')


class Conversation(list):
    """
    A class representing a conversation. A conversation is an ordered exchange
    of messages between two nodes.

    It is composed by the two nodes and a list of (Node, Frames) tuple.
    Frame list mostly begin whith a request followed by one or many responses.
    """

    @typecheck
    def __init__(self, nodes: (Node, Node)):
        """
        Function to initialize a Conversation object with its nodes

        :param nodes: The communicating nodes
        :type nodes: (Node, Node)
        """
        self._nodes = nodes

    @property
    def nodes(self):
        """
        Function to get the nodes as a binary tuple

        :return: The tuple of nodes
        :rtype: (Node, Node)
        """
        return self._nodes

    @nodes.setter
    def nodes(self, value):
        raise AttributeError('Setting nodes attribute is not allowed')

    def __bool__(self):
        """
        Function for when we check that the conversation exist

        :return: Always True
        :rtype: bool
        """
        return True


class TestCase:
    """
    A class handling a test case for an analysis
    """

    class Stop(Exception):
        """
        Exception thrown when the execution is finished, can finish sooner than
        the end of the TC if it failed
        """
        pass

    @typecheck
    def __init__(self, conv_list: list_of(Conversation)):
        """
        Initialize a test case, the only thing that it needs for
        interoperability testing is a list of frame

        :param conv_list: The list of conversations to analyze
        :type conv_list: [Conversation]
        """

        # Initialize its verdict instance and its list of conversations
        self._verdict = Verdict()

        # Prepare the parameters
        self._conversations = conv_list
        self._iter = None
        self._frame = None
        self._node = None

        # Prepare the values to return after a TC is finished
        self._text = ''
        self._failed_frames = []
        self._exceptions = []

    @typecheck
    def match(
        self,
        node_name: str,
        template: Value,
        verdict: optional(is_verdict) = 'inconc',
        msg: str = ''
    ) -> bool:
        """
        Abstract function to match the current frame value with a template

        :param node_name: The node_name of the packet
        :param template: The template to confront with current frame value
        :param verdict: The verdict to put if it matches
        :param msg: The message to associated with the verdict
        :type node_name: str
        :type template: Value
        :type verdict: str
        :type msg: str

        :return: True if the current frame value matched the given template
                 False if not
        :rtype: bool
        """

        # If we're expecting a frame but it's the end of conversation
        if not self._iter:
            self.set_verdict(
                verdict,
                'Expected %s from the %s' % (template, node_name)
            )

            # Add this frame's id to the failed frames
            self._failed_frames.append(self._frame['id'])
            self.log('ENCOUNTER FAILED FRAME! : %d' % self._frame['id'])

            # Frame value didn't match the template (error in fact)
            return False

        # Check the node
        if not self.check_node(node_name):

            # If a verdict is given, put it
            if verdict is not None:
                self.set_verdict(
                    verdict,
                    'Expected %s from the %s' % (template, node_name)
                )

            # Add this frame's id to the failed frames
            self._failed_frames.append(self._frame['id'])
            self.log('ENCOUNTER FAILED FRAME! : %d' % self._frame['id'])

            # Frame value didn't match the template (error in fact)
            return False

        # Check the template
        if template:
            protocol = self.protocol()
            diff_list = DifferenceList(self._frame[protocol])

            # If it matches
            if template.match(self._frame[protocol], diff_list):
                if verdict is not None:
                    self.set_verdict('pass', 'Match: %s' % template)

            # If it didn't match
            else:
                if verdict is not None:
                    def callback(path, mismatch, describe):
                        self.log(
                            "             %s: %s\n"
                            %
                            (
                                ".".join(path),
                                type(mismatch).__name__
                            )
                        )
                        self.log(
                            "                 got:        %s\n"
                            %
                            mismatch.describe_value(describe)
                        )
                        self.log(
                            "                 expected: %s\n"
                            %
                            mismatch.describe_expected(describe)
                        )

                    # Put the verdict
                    self.set_verdict(verdict, 'Mismatch: %s' % template)
                    diff_list.describe(callback)

                # Add this frame's id to the failed frames
                self._failed_frames.append(self._frame['id'])

                # Frame value didn't match the template
                return False

        # If it matched, return True
        return True

    @typecheck
    def next(self, optional: bool = False):
        """
        Switch to the next frame

        :param optional: If we have to get a next frame or not
        :type optional: bool
        """
        try:
            self._node, self._frame = next(self._iter)
            self.log((self._node, self._frame))

        except StopIteration:
            if not optional:
                self._iter = None
                self.log('<Frame  ?>')
                self.set_verdict('inconc', 'premature end of conversation')

        except TypeError:
            raise self.Stop()

    @typecheck
    def log(self, msg: anything):
        """
        Log a message

        :param msg: The message to log, can be of any type
        :type msg: object
        """
        text = str(msg)
        self._text += text if text.endswith('\n') else (text + '\n')

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
        self.log('  [%s] %s' % (format(verdict, "^6s"), msg))

    @typecheck
    def run_test_case(self) -> (
        str,
        list_of(int),
        str,
        list_of((type, Exception, is_traceback))
    ):
        """
        Run the test case

        :return: A tuple with the informations about the test results which are
                 - The verdict as a string
                 - The list of the result important frames
                 - A string for extra informations
                 - A list of typles representing the exceptions that occured
        :rtype: (str, [int], str, [(type, Exception, traceback)])
        """

        # Run the test case for every conversations
        for conv in self._conversations:

            try:

                # Get an iterator on the current conversation frames
                self._iter = iter(conv)
                self.next()

                # Run the test case
                self.run()

                # NOTE: With new implementation, we can have useless frames at
                #       the end of a conversation. We have to put them into
                #       ignored frames or just ignore them if there are some
                #       like we are doing right now.
                #
                # # Ensure we're at the end of the communication
                # try:
                #     self.log(next(self.__iter))
                #     self.set_verdict('inconc', 'unexpected frame')
                # except StopIteration:
                #     pass

            except self.Stop:
                # Ignore this testcase result if the first frame gives an
                # inconc verdict
                if all((
                    self._verdict.get_value() == 'inconc',
                    self._frame == conv[0]
                )):
                    self.set_verdict('none', 'no match')

            except Exception:

                # Get the execution informations, it's a tuple with
                #     - The type of the exception being handled
                #     - The exception instance
                #     - The traceback object
                exc_info = sys.exc_info()

                # Add those exception informations to the list
                self._exceptions.append(exc_info)

                # Put the verdict and log the exception
                self.set_verdict('error', 'unhandled exception')
                self.log(exc_info[1])

        # Return the results
        return (
            self._verdict.get_value(),
            self._failed_frames,
            self._text,
            self._exceptions
        )

    @classmethod
    @typecheck
    def get_test_purpose(cls) -> str:
        """
        Get the purpose of this test case

        :return: The purpose of this test case
        :rtype: str
        """
        if cls.__doc__:
            ok = False
            for line in cls.__doc__.splitlines():
                if ok:
                    return line
                if line == 'Objective:':
                    ok = True
        return ''

    @classmethod
    @typecheck
    def protocol(cls) -> is_protocol:
        """
        Get the protocol corresponding to this test case. This has to be
        implemented into the protocol's common test case class.

        :return: The protocol on which this TC will occur
        :rtype: Value
        """
        raise NotImplementedError()

    @classmethod
    @typecheck
    def generate_nodes(cls, frame: Frame) -> (Node, Node):
        """
        Generate nodes from the first frame of the conversation. This has to be
        implemented into the protocol's common test case class.

        :return: The generated nodes
        :rtype: (Node, Node)
        """
        raise NotImplementedError()

    @classmethod
    @typecheck
    def frame_node(cls, frame: Frame) -> Node:
        """
        Get the node corresponding to a frame. This has to be implemented into
        the protocol's common test case class.

        :return: The generated node of this frame
        :rtype: Node
        """
        raise NotImplementedError()

    @typecheck
    def check_node(self, node_name: str) -> bool:
        """
        Function to check if the sender of a frame is the correct one. This has
        to be implemented into the protocol's common test case class.

        :param node_name: The name of the sender
        :type node_name: str

        :return: True if the sender's name and value corresponds
        :rtype: bool
        """
        raise NotImplementedError

    @classmethod
    @typecheck
    def stimulis(cls) -> list_of(Value):
        """
        Get the stimulis of this test case. This has to be be implemented into
        each test cases class.

        :return: The stimulis of this TC
        :rtype: [Value]
        """
        raise NotImplementedError()


class Filter:
    """
    Filter class to filter and give conversations from frame list
    """

    @typecheck
    def __init__(
        self,
        capture: Capture,
        testcase: is_tc_subclass
    ):
        """
        Initialize the Filter with the capture object and the corresponding
        test case

        :param capture: The capture which will be filtered
        :param testcase: The TC object to get the stimulis and the protocol
        :type capture: Capture
        :type testcase: type (subclass of TestCase)

        :raises ValueError: If there is no stimuli given
        """

        # Get informations from the test case
        stimulis = testcase.stimulis()
        protocol = testcase.protocol()

        # The attribute to store conversations
        self._conversations = []
        # Ignored is defined a little lower

        # If there is no stimuli at all
        if len(stimulis) == 0:
            raise ValueError('Expected at least one stimuli')

        # Get the frames filtered on the protocol
        frames, self._ignored = Frame.filter_frames(capture.frames, protocol)

        # Get a counter of the current stimuli
        sti_count = 0
        current_conversation = None
        nb_stimulis = len(stimulis)
        for frame in frames:

            # If the frame matches a stimuli
            if stimulis[sti_count].match(frame[protocol]):

                # If it's the first stimuli
                if sti_count == 0:

                    # If there is already a conversation pending, save it
                    if current_conversation:
                        self._conversations.append(current_conversation)

                    # Generate the two nodes as binary tuple
                    nodes = testcase.generate_nodes(frame)

                    # And create the new one
                    current_conversation = Conversation(nodes)

                # If intermediate stimulis, just increment the counter
                sti_count = (sti_count + 1) % nb_stimulis

            # If there is a current_conversation, put the frame into it
            if current_conversation:
                node = testcase.frame_node(frame)
                current_conversation.append((node, frame))

            # If no conversation pending
            else:
                self._ignored.append(frame)

        # At the end, if there is a current conversation pending, close it
        if current_conversation:

            # If not all stimulis were consumed
            if sti_count != 0:
                raise FilterError(
                    'Not all stimulis were consumed, %d left and next one should have been %s'
                    %
                    (
                        nb_stimulis - sti_count,
                        stimulis[sti_count]
                    )
                )

            # Close the current conversation by adding it to list
            self._conversations.append(current_conversation)

    @property
    def conversations(self):
        """
        Function to get the conversations as a list

        :return: The lsit of conversation
        :rtype: [Conversation]
        """
        return self._conversations

    @conversations.setter
    def conversations(self, value):
        raise AttributeError('Setting conversations attribute is not allowed')

    @property
    def ignored(self):
        """
        Function to get the ignored frames as a list

        :return: The ignored frames that were filtered
        :rtype: [Frame]
        """
        return self._ignored

    @ignored.setter
    def ignored(self, value):
        raise AttributeError('Setting ignored attribute is not allowed')


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

        .. note::
            Assumptions are the following:
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
    ) -> (str, str, list_of(int), str, list_of(
             (type, Exception, is_traceback)
         )):
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
                 - A list of typles representing the exceptions that occured
        :rtype: (str, str, [int], str, [(type, Exception, traceback)])

        :raises FileNotFoundError: If the test env of the tc is not found
        :raises ReaderError: If the capture didn't manage to read and decode
        :raises ObsoleteTestCase: If the test case if obsolete

        .. example::
            ('TD_COAP_CORE_03', 'fail', [21, 22], 'verdict description', '')

        .. note::
            Allows multiple ocurrences of the testcase, returns as verdict:
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

            # Get the capture from the file
            capture = Capture(filename)

            # Get the conversations from the filter
            frame_filter = Filter(capture, test_case_class)

            # Initialize the TC with the list of conversations
            test_case = test_case_class(frame_filter.conversations)

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
            return (tc_id, verdict, rev_frames, extra, exceptions)


if __name__ == "__main__":
    # WARNING: The underlying code can work wrong if this module is directly
    #          launched as main.
    #
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
    # result = Analyzer('tat_coap').analyse(
    #     '/'.join((
    #         'tests',
    #         'test_dumps',
    #         'TD_COAP_CORE_02_PASS.pcap'
    #     )),
    #     'TD_COAP_CORE_02'
    # )
    # print(
    #     result
    # )
    # if len(result[4]) > 0:
    #     import traceback
    #     traceback.print_tb(result[4][0][2])
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
    #     except ReaderError:
    #         print(tc[0] + " doesn't have a dump file associated to it")
    #     print('############################################################')
    #     print('')
    # capture = Capture(
    #     '/'.join((
    #         'tests',
    #         'test_dumps',
    #         'TD_COAP_CORE_01_PASS.pcap'
    #     ))
    # )
    # stimulis = [
    #     CoAP(type='con', code='get'),
    #     CoAP(type='con', code='get')
    # ]
    # from ttproto.tat_coap.testcases.td_coap_core_01 import TD_COAP_CORE_01
    # from ttproto.tat_coap.common import CoAPTestCase
    # assert type(TD_COAP_CORE_01) == type
    # assert issubclass(TD_COAP_CORE_01, CoAPTestCase)
    # assert issubclass(CoAPTestCase, TestCase)
    # assert issubclass(TD_COAP_CORE_01, TestCase)
    # coap_filter = Filter(capture, TD_COAP_CORE_01)
    # print('##### Generated conversations')
    # for conv in coap_filter.conversations:
    #     print(conv)
    # print('##### Ignored frames')
    # print(coap_filter.ignored)
    # coap_analyser = Analyzer('tat_coap')
    # for test_id, _, _ in coap_analyser.get_implemented_testcases():
    #     result = coap_analyser.analyse(
    #             '/'.join((
    #                 'tests',
    #                 'test_dumps',
    #                 test_id + '_PASS.pcap'
    #             )),
    #             test_id
    #         )
    #     if result[1] != 'pass':
    #         print(result)
    #         if len(result[4]) > 0:
    #             import traceback
    #             traceback.print_tb(result[4][0][2])
    pass
