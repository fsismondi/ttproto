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
import sys
import traceback

from os import path, environ
from importlib import import_module
import logging

from ttproto import PACKAGE_DIR
from ttproto.core.data import Data, DifferenceList, Value
from ttproto.core.dissector import Frame, Capture, is_protocol, ProtocolNotFound
from ttproto.core.exceptions import Error
from ttproto.core.typecheck import typecheck, tuple_of, optional, anything, list_of
from ttproto.core.lib.all import *
from ttproto.core.lib.readers.yaml import YamlReader

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(environ.get('LOG_LEVEL', logging.DEBUG))

__all__ = [
    'Verdict',
    'Node',
    'Conversation',
    'TestCase',
    'Analyzer'
]

TESTCASES_SUBDIR = 'testcases'
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
        inspect.isclass(arg) and issubclass(arg, TestCase)
    ))


class Verdict:
    """
    A class handling the verdict for an analysis

    Known verdict values are:
     - 'none': No verdict set yet
     - 'pass': The NUT fulfilled the test purpose
     - 'inconclusive': The NUT did not fulfill the test purpose but did not display
                 bad behaviour
     - 'fail': The NUT did not fulfill the test purpose and displayed a bad
               behaviour
     - 'aborted': The test execution was aborted by the user
     - 'error': A runtime error occured during the test

    At initialisation time, the verdict is set to None. Then it can be updated
    one or multiple times, either explicitly calling set_verdict() or
    implicitly if an unhandled exception is caught by the control module
    (error verdict) or if the user interrupts the test manually (aborted
    verdict).

    Each value listed above has precedence over the previous ones. This means
    that when a verdict is updated, the resulting verdict is changed only if
    the new verdict is worse than the previous one.
    """

    __values = ('none', 'pass', 'inconclusive', 'fail', 'aborted', 'error')

    @typecheck
    def __init__(self, initial_value: optional(str) = None):
        """
        Initialize the verdict value to 'none' or to the given value

        :param initial_value: The initial value to put the verdict on
        :type initial_value: optional(str)
        """
        self.__value = 0
        self.__message = ''
        self.__traceback = []
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

        self.__traceback.append((new_verdict, message))
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

    def get_traceback(self):
        """
        Get the complete traceback of all partial verdicts

        :return: list of partial verdicts, with their messages
        :rtype: list of tuples: [(str, str)]
        """
        return self.__traceback

    @typecheck
    def __str__(self) -> str:
        """
        Get the value of the verdict as string for printing it

        :return: The value of the verdict as a string
        :rtype: str
        """
        return self.__values[self.__value]


class Node:
    """
    A node object is any communicating entity, taking part
    on a conversation. It can be a node, a client/server, an host, etc.

    It has a name (ex: client, node1, iut2, border_router) and an
    associated template, like an IP or a MAC address template for example.
    """

    @typecheck
    def __init__(self, name: str, value: Value):
        """
        Create an node object

        :param name: The name of this node
        :param value: The template associated to this node
        :type name: str
        :type value: Value
        """
        self._name = name
        self._value = value

    def __repr__(self):
        """
        Get the string representation of this node

        :return: String representation of this node
        :rtype: str
        """
        return "Node \"%s\" identification pattern is: %s" % (self._name, self._value)

    @property
    def name(self):
        """
        Function to get the name

        :return: The name
        :rtype: str
        """
        return self._name

    @property
    def value(self):
        """
        Function to get the template

        :return: The template
        :rtype: Value
        """
        return self._value


class Conversation(list):
    """
    A class representing a conversation. A conversation is an ordered exchange
    of messages between at least two nodes.

    It is composed by the nodes and a list of Frames.
    """

    @typecheck
    def __init__(self, nodes: list_of(Node)):
        """
        Function to initialize a Conversation object with its nodes

        :param nodes: The communicating nodes
        :type nodes: [Node]

        :raises ValueError: If not enough nodes received (less than 2)
        """

        # If not enough nodes
        if len(nodes) < 2:
            raise ValueError(
                'At least 2 nodes are required but %d received'
                %
                len(nodes)
            )

        # The node dictionary
        self._nodes = {}
        for node in nodes:
            self._nodes[node.name] = node.value

    @property
    def nodes(self):
        """
        Function to get the nodes as a dictionnary

        :return: The dictionnary of nodes
        :rtype: {str: Template}
        """
        return self._nodes

    def __bool__(self):
        """
        Function for when we check that the conversation exist

        :return: Always True
        :rtype: bool
        """
        return True


class TestCase(object):
    """
    A class handling a test case for an analysis.
    Test cases in ttproto context is a set of checks steps of a test specification
    """

    class Stop(Exception):
        """
        Exception thrown when the execution is finished, can finish sooner than
        the end of the TC if it failed
        """
        pass

    @typecheck
    def __init__(self, capture: Capture):
        """
        Initialize a test case, only input needed is a list of frames

        :param conv_list: The list of conversations to analyze
        :type conv_list: [Conversation]
        """

        # Initialize its verdict instance and its list of conversations
        self._verdict = Verdict()

        # Prepare the parameters
        self._capture = capture
        self._conversations = []
        self._ignore_frames = []
        self._nodes = None
        self._iter = None
        self._frame = None

        # Prepare the values to return after a TC is finished
        # TODO keep & use test_stack (structured representation of the logs in an array) and delete self._text (string)
        self._text = ''
        self._text_stack = []
        self._failed_frames = []
        self._exceptions = []

    @typecheck
    def __not_matching(self, verdict: optional(is_verdict), message: str) -> bool:

        # Put the verdict
        if verdict:
            self.set_verdict(verdict, message)

        # Add this frame's id to the failed frames
        self._failed_frames.append(self._frame['id'])
        # self.log('failed frames: %d' % self._frame['id'])
        self.log(message)
        # Always return False
        return False

    @typecheck
    def match(
            self,
            node_name: optional(str),
            template: Value,
            on_mismatch_verdict: optional(is_verdict) = 'inconclusive',
            on_mismatch_msg: str = ''
    ) -> bool:
        """
        Abstract function to match the current frame value with the template passed as argument

        :param node_name: The node source of the frame
        :param template: The template to match against the frame value
        :param on_mismatch_verdict: Verdict applied when there's a mismatch, normally used with inconclusive, fail
        or None
        :param on_mismatch_msg: Message applied when there's a mismatch
        :type node_name: str
        :type template: Value
        :type on_mismatch_verdict: str
        :type on_mismatch_msg: str

        :return: True if the current frame value matched the given template
                 False if not
        :rtype: bool
        """

        # If no more frames for this conversation
        if not self._iter:
            return self.__not_matching(
                on_mismatch_verdict,
                'Expected %s from the %s but premature end of conversation' % (
                    template, node_name)
            )

        # Check the node
        if node_name is not None:
            try:
                node_template = self._nodes[node_name]

            except KeyError:
                return self.__not_matching(
                    on_mismatch_verdict,
                    'No node %s was not found. Check list of nodes defined for the test case'
                    % (node_name)
                )

            # check the sender (node) is as expected
            try:
                if not node_template.match(self._frame[node_template.__class__]):
                    # The node isn't matching
                    return self.__not_matching(
                        on_mismatch_verdict,
                        'Sender doesnt match. Expected %s pattern for the %s'
                        % (node_template, node_name)
                    )
            except ProtocolNotFound:
                return self.__not_matching(
                    on_mismatch_verdict,
                    'Expected %s into protocol %s but it was not found'
                    % (node_template, node_template.__class__.__name__)
                )

        # Here check the template passed
        protocol = self.get_protocol()
        diff_list = DifferenceList(self._frame[protocol])

        if template.match(self._frame[protocol], diff_list):  # it matches
            if on_mismatch_verdict is not None:
                partial_verdict_message = ' Match: %s' % template
                self.set_verdict('pass', str(self._frame) + partial_verdict_message)

        else:  # mismatch
            if on_mismatch_verdict is not None:
                def callback(path, mismatch, describe):
                    self.log("             %s: %s\n" % (".".join(path), type(mismatch).__name__))
                    # for i in diff_list:
                    #     self.log("             List Diff Item: %s\n" % (i))
                    self.log("                 got:      %s\n" % mismatch.describe_value(describe))
                    self.log("                 expected: %s\n" % mismatch.describe_expected(describe))

                if on_mismatch_msg != '':
                    partial_verdict_message = on_mismatch_msg
                else:
                    partial_verdict_message = template

                # Put the verdict
                self.set_verdict(on_mismatch_verdict, "%s Mismatch: %s" %(str(self._frame),partial_verdict_message))
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
            self._frame = next(self._iter)
            self.log(self._frame)

        except StopIteration:
            if not optional:
                self._iter = None
                self.log('<Frame  ?>')
                self.set_verdict('inconclusive', 'premature end of conversation')

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
        self._text_stack.append(msg)
        self._text += text if text.endswith('\n') else (text + '\n')

    @typecheck
    def set_verdict(self, verdict: is_verdict, msg):
        """
        Update the current verdict of the current test case

        :param verdict: The new verdict
        :param msg: The message to associate with the verdict

        """
        msg_fix = ''
        if msg is None:
            pass
        elif type(msg) is str:
            msg_fix = msg
            self.log('  [%s] %s' % (format(verdict, "^6s"), msg_fix))
        elif type(msg) is list:
            while msg:
                msg_fix += msg.pop() + '\n'

        # verdict msg can now log more that one line of messages
        self._verdict.update(verdict, msg_fix)

    @typecheck
    def run_test_case(self) -> (
            str,
            list_of(int),
            str,
            list_of((str, str)),
            list_of((type, Exception, is_traceback))
    ):
        """
        Run the test case

        :return: A tuple with the informations about the test results which are
                 - The verdict as a string
                 - The list of the result important frames
                 - A string with the log of the test case
                 - A list of all the partial verdicts and their messages
                 - A list of typles representing the exceptions that occurred
        :rtype: (str, [int], str,[(str,str)], [(type, Exception, traceback)])
        """
        # Next line is before for 6lowpan TC, where nodes_identification_templates
        # is not generic.
        TestCase.get_nodes_identification_templates = self.get_nodes_identification_templates

        # Pre-process / filter conversations corresponding to the TC

        self._conversations, self._ignored = self.preprocess(
            capture=self._capture,
            expected_frames_pattern=self.get_stimulis()
        )

        # print("----conversations----")
        # print(self._conversations)
        # print("----ignored----")
        # print(self._ignored)

        if self._conversations == [[]] or self._conversations == []:
            self.set_verdict(
                'inconclusive',
                'Capture doesnt match expected pattern: \n\tgot %s, \n\texpected %s' %
                (str(self._capture.frames), str(self.get_stimulis()))
            )

        else:
            # Run the test case for every conversations
            for conv in self._conversations:
                if logger.getEffectiveLevel() == logging.DEBUG:
                    for frame in conv: logger.debug(frame)
                try:
                    # Get an iterator on the current conversation frames
                    # and its list of nodes
                    self._iter = iter(conv)
                    self._nodes = conv.nodes
                    self.next()

                    # Run the test case
                    self.run()

                except self.Stop:
                    # Ignore this testcase result if the first frame gives an
                    # inconclusive verdict
                    if all((
                                self._verdict.get_value() == 'inconclusive',
                                self._frame == conv[0]
                    )):
                        self.set_verdict('none', 'no match')

                except Exception as e:
                    # Get the execution information, it's a tuple with
                    #     - The type of the exception being handled
                    #     - The exception instance
                    #     - The traceback object
                    _exception_type, _exception_value, _exception_traceback = sys.exc_info()

                    logger.error(e)
                    traceback.print_exc(file=sys.stdout)

                    # Add those exception information to the list
                    self._exceptions.append((
                        _exception_type,
                        _exception_value,
                        _exception_traceback
                    ))

                    # Put the verdict and log the exception
                    self.set_verdict('error', 'unhandled exception')
                    self.log(_exception_value)

        # Return the results
        return (
            self._verdict.get_value(),
            self._failed_frames,
            self._text,
            self._verdict.get_traceback(),
            self._exceptions,
        )

    @classmethod
    @typecheck
    def get_test_purpose(cls) -> str:
        """
        Get the purpose of this test case

        Supports old formats of test description in yaml and new one introduced by ioppytest

        - Old test case description format goes like this (nested):
            {'TD_COAP_CORE_01': {'cfg': 'CoAP_CFG_BASIC', 'obj': 'Perform GET transaction(CON mode)', 'pre': ...}}
        - New test case description format (used by ioppytest), goes like this (flat):
            {'testcase_id': 'TD_LWM2M_1.0_INT_203', 'configuration': 'LWM2M_CFG_01', 'objective': ....}}


        >>> from ttproto.tat_lwm2m.testcases.td_lwm2m_1_int_203 import TD_LWM2M_1_INT_203
        >>> TD_LWM2M_1_INT_203.get_test_purpose()
        "['Quering the Resources values of Device Object (ID:3) on the Client in TLV format', ['Manufacturer Name (id:0)', 'Model number (ID:1)', 'Serial number (ID:2)', 'Firware Version (ID:3)', 'Error Code (ID:11)', 'Supported Binding and Modes (ID:16)']]"

        >>> from ttproto.tat_coap.testcases.td_coap_core_01 import TD_COAP_CORE_01
        >>> TD_COAP_CORE_01.get_test_purpose()
        'Perform GET transaction(CON mode)'

        :return: The purpose of this test case
        :rtype: str
        """
        if cls.__doc__:

            # Get the Yaml reader
            yaml_reader = YamlReader(cls.__doc__, raw_text=True)

            # Then get the dictionary representation of the tc documentation
            doc_as_dict = yaml_reader.as_dict

            # Into this dict, get the test objective
            if len(doc_as_dict) == 1:  # nested format
                return str(doc_as_dict[cls.__name__]['obj'])
            else:  # flat format
                return str(doc_as_dict['objective'])

        return ''

    @classmethod
    @typecheck
    def get_protocol(cls) -> is_protocol:
        """
        Get the protocol corresponding to this test case. This has to be
        implemented into the protocol's common test case class.

        This protocol's layer will be the one on which we will do the matching
        so it should be the lowest one that we are testing.


        >>> from ttproto.tat_coap.testcases.td_coap_core_01 import TD_COAP_CORE_01
        >>> TD_COAP_CORE_01.get_protocol()
        <class 'ttproto.core.lib.inet.coap.CoAP'>

        :return: The protocol on which this TC will occur
        :rtype: Value
        """
        raise NotImplementedError()

    @classmethod
    @typecheck
    def preprocess(
            cls,
            capture: Capture,
            expected_frames_pattern: list_of(Value)
    ) -> (list_of(Conversation), list_of(Frame)):
        """
        Pre-process and filter the frames of the capture into test case related
        conversations. This has to be implemented into the protocol's common
        test case class.
        This method depends on the protocol features, so it cannot be
        implemented in a generic way.
        """
        raise NotImplementedError()

    @classmethod
    @typecheck
    def get_stimulis(cls) -> list_of(Value):
        """
        Get the stimulis of this test case. This has to be be implemented into
        each test cases class.

        :return: The stimulis of this TC
        :rtype: [Value]
        """
        raise NotImplementedError()

    @classmethod
    @typecheck
    def get_nodes_identification_templates(cls) -> list_of(Node):
        """
        Get the nodes of this test case. This has to be be implemented into
        each test cases class.

        :return: The nodes of this TC
        :rtype: [Node]
        """
        raise NotImplementedError()


class Analyzer:
    """
        Class for the analyzer tool.

        Basically this objects allow you to
        1. import all/certain testcases
        2. get testcases objects
        3. analyze pcaps files with network traces against testcases

    """

    @typecheck
    def __init__(self, test_env: str = 'tat_*'):
        """
        Initialization function for the analyzer, just fetch the test env
        in which we will get the test description's implementation

        :param test_env: The test environment which is the TAT package name
        :type test_env: str

        :raises NotADirectoryError: If the test environemnt isn't found
        """

        self.testcases_dir = path.join(
            PACKAGE_DIR,
            test_env,
            TESTCASES_SUBDIR
        )

        # if test_env provided then it should be a valid one
        if test_env != 'tat_*' and not path.isdir(self.testcases_dir):
            raise NotADirectoryError("Not a valid test environment: %s" % test_env)

    @typecheck
    def __get_testcase_object_from_pathname(self, testcase_path: str):
        if len(testcase_path.split(path.sep)) < 3:
            raise FileNotFoundError('Impossible to get testcase object from %s' % testcase_path)

        # we need to build a ttproto.tat_coap.testcases.td_coap_core_01 from ttproto/tat_coap/testcases/td_coap_core_01

        # Get the name of the file
        filename = testcase_path.split(path.sep)[-1]
        superdir = testcase_path.split(path.sep)[-2]
        test_environment = testcase_path.split(path.sep)[-3]

        # Get the name of the module
        modname = filename[:(-1 * len(TC_FILE_EXTENSION))]

        # Build the module relative name
        mod_rel_name = '.'.join([
            'ttproto',
            test_environment,
            superdir,
            modname
        ])

        # Note that the module is always lower case and the plugin (class)
        # is upper case (ETSI naming convention)

        return getattr(import_module(mod_rel_name), modname.upper())

    @typecheck
    def __get_testcases_from_pathname(self, search: str):
        """
        Get list of test cases objects from the right test suite search

        :param testcases: List in which we will add the test cases
        :param search: The research query, can be a single TC or the wildcard
                       to select all the test cases
        :type testcases: [type]
        :type search: str
        """
        testcases = []

        # Build the search query
        search_query = path.join(
            self.testcases_dir,
            search
        )

        # Fetch files using the search query
        result = glob.glob(search_query)

        # If no test case found
        if len(result) == 0:
            raise FileNotFoundError(
                'No test case found for: "%s"' % search_query
            )

        # If the search query is the wildcard, sort the list
        elif search == EVERY_TC_WILDCARD:
            result.sort()

        # For every file found
        for filepath in result:
            tc = self.__get_testcase_object_from_pathname(filepath)
            if tc:
                testcases.append(tc)

        return testcases

    @typecheck
    def import_test_cases(self, testcases: optional(list_of(str)) = None) -> list:
        """
        Imports test cases classes from TESTCASES_DIR

        :param testcases: The wanted test cases as a list of string

        :return: List of test cases class in the same order than the param list

        :raises FileNotFoundError: If no test case was found

        .. note::
            Assumptions are the following:
                - Test cases are defined inside a .py file, each file contains only one test case
                - All test cases must be named td_*
                - All test cases are contained into ttproto/[env]/testcases
                - Filenames corresponds to the TC id in lower case
                - Class names corresponds to the TC id
        """

        # The return values
        tc_fetched = []

        # If no TCs provided, fetch all the test cases found
        if not testcases:
            tc_fetched = self.__get_testcases_from_pathname(EVERY_TC_WILDCARD)

        # If testcases list are provided, fetch those
        else:
            # For every test case given
            for test_case_name in testcases:
                tc_name_query = test_case_name.lower() + TC_FILE_EXTENSION
                tc_fetched += self.__get_testcases_from_pathname(tc_name_query)

        # Return the test cases classes
        return tc_fetched

    @typecheck
    def get_implemented_testcases(
            self,
            testcases: optional(list_of(str)) = None,
            verbose: bool = False
    ) -> list_of((str, str, str, str)):
        """
        Get more informations about the test cases

        :param testcases: A list of test cases to get their informations
        :param verbose: True if we want more informations about the TC
        :type testcase_id: optional([str])
        :type verbose: bool

        :raises FileNotFoundError: If one of the test case is not found

        :return: List of descriptions of test cases composed of:
                    - tc_identifier
                    - tc_objective
                    - tc_sourcecode
                    - tc_doc
        :rtype: [(str, str, str, str)]
        """

        # The return value
        ret = []

        # Get the tc classes
        tc_classes = self.import_test_cases(testcases)

        # Add the infos of each of them to the return value
        for tc in tc_classes:

            # If verbose is asked, we provide the source code and doc too
            source_code = ''
            source_doc = ''
            if verbose:
                source_code = inspect.getsource(tc)
                source_doc = inspect.getdoc(tc)

            # Add the tuple to the return value
            ret.append(
                (tc.__name__, tc.get_test_purpose(), source_code, source_doc)
            )

        # Return the list of tuples
        return ret

    @typecheck
    def analyse(
            self,
            filename: str,
            tc_id: str
    ) -> (str, str, list_of(int), str, list_of((str, str)), list_of((type, Exception, is_traceback))):
        """
        Analyse a dump file associated to a test case

        :param filename: The name of the file to analyse
        :param tc_id: The unique id of the test case to confront the given file
        :type filename: str
        :type tc_id: str

        :return: A tuple with the information about the analysis results:
                 - The id of the test case
                 - The verdict as a string
                 - The list of the result important frames
                 - A string with logs
                 - A list of all the partial verdicts
                 - A list of tuples representing the exceptions that occurred
        :rtype: (str, str, [int], str,[(str, str)], [(type, Exception, traceback)])

        :raises FileNotFoundError: If the test env of the tc is not found
        :raises ReaderError: If the capture didn't manage to read and decode
        :raises ObsoleteTestCase: If the test case if obsolete

        .. example::
            ('TD_COAP_CORE_03', 'fail', [21, 22], [('fail', "some comment"),('fail', "some other comment")] , 'verdict description', '')

        .. note::
            Allows multiple occurrences of executions of the testcase, returns as verdict:
                - fail: if at least one on the occurrences failed
                - inconclusive: if all occurrences returned a inconclusive verdict
                - pass: all occurrences are inconclusive or at least one is PASS and
                        the rest is inconclusive
        """

        # Get the test case class
        test_case_class = self.import_test_cases([tc_id])
        assert len(test_case_class) == 1
        test_case_class = test_case_class[0]

        # Disable name resolution for performance improvements
        with Data.disable_name_resolution():
            # Get the capture from the file
            capture = Capture(filename)
            # Initialize the TC with the list of conversations
            test_case = test_case_class(capture)
            verdict, rev_frames, log, partial_verdicts, exceps = test_case.run_test_case()

            # print('##### capture')
            # print(capture)
            # print('#####')
            #
            # # Here we execute the test case and return the result
            #
            # print('##### Verdict given')
            # print(verdict)
            # print('#####')
            # print('##### Review frames')
            # print(rev_frames)
            # print('#####')
            # print('##### Text')
            # print(log, partial_verdicts)
            # print('#####')
            # print('##### Exceptions')
            # print(exceptions)
            # print('#####')

            return tc_id, verdict, rev_frames, log, partial_verdicts, exceps


if __name__ == "__main__":
    from os import getcwd, path

    #
    # analyzer = Analyzer('tat_6lowpan')
    #
    # params = './tmp/TD_6LOWPAN_HC_01.pcap', 'TD_6LOWPAN_HC_01'
    # tc_name, verdict, rev_frames, str_log, lst_log, excepts = analyzer.analyse(params[0], params[1])
    # print('##### TC name')
    # print(tc_name)
    # print('#####')
    # print('##### Verdict given')
    # print(verdict)
    # print('#####')
    # print('##### Review frames')
    # print(rev_frames)
    # print('#####')
    # print('##### Text')
    # print(str_log)
    # print('##### Partial verdicts')
    # for s in lst_log:
    #     print(str(s))
    # print('#####')
    # print('##### Exceptions')
    # for e in excepts:
    #     e1, e2, e3 = e
    #     print(repr(traceback.format_exception(e1, e2, e3)))
    #
    # print('#####')


    analyzer = Analyzer('tat_coap')

    # params = './tests/test_dumps/AnalyzerTests/coap_core/TD_COAP_CORE_01_pass.pcap', 'TD_COAP_CORE_01'
    # params = './tests/test_dumps/coap_core/TD_COAP_CORE_01_pass.pcap', 'TD_COAP_CORE_01'
    params = './tests/test_dumps/coap_core/TD_COAP_CORE_03_FAIL_No_CoAPOptionContentFormat.pcap', 'TD_COAP_CORE_03'
    # params = './tmp/TD_COAP_CORE_23_fail.pcap', 'TD_COAP_CORE_23'
    # params = './tests/test_dumps/AnalyzerTests/coap_core/TD_COAP_CORE_03_FAIL_No_CoAPOptionContentFormat.pcap', 'TD_COAP_CORE_03'
    tc_name, verdict, rev_frames, str_log, lst_log, excepts = analyzer.analyse(params[0], params[1])
    print('##### TC name')
    print(tc_name)
    print('#####')
    print('##### Verdict given')
    print(verdict)
    print('#####')
    print('##### Review frames')
    print(rev_frames)
    print('#####')
    print('##### Text')
    print(str_log)
    print('##### Partial verdicts')
    for s in lst_log:
        print(str(s))
    print('#####')
    print('##### Exceptions')
    for e in excepts:
        e1, e2, e3 = e
        print(repr(traceback.format_exception(e1, e2, e3)))

    print('#####')
