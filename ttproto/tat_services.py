import os
import time
import json
import base64
import hashlib
import logging

from collections import OrderedDict

from ttproto import LOG_LEVEL
from ttproto.core.lib.all import *
from ttproto.core.analyzer import Analyzer
from ttproto.core.dissector import Capture, get_dissectable_protocols
from ttproto.core.typecheck import typecheck, optional, either
from ttproto.utils.pcap_filter import remove_first_frames

ALLOWED_PROTOCOLS_FOR_ANALYSIS = ['coap', '6lowpan', 'onem2m', 'lwm2m']

# Directories
from ttproto import DATADIR
from ttproto import TMPDIR
from ttproto import LOGDIR

# Prefix and suffix for the hashes
HASH_PREFIX = 'tt'
HASH_SUFFIX = 'proto'
TOKEN_LENGTH = 28

# # # AUXILIARY FUNCTIONS # # #

logger = logging.getLogger('tat|ttproto_api')
logger.setLevel(LOG_LEVEL)


def analyze_capture(filename, protocol, testcase_id, output_filename):
    """
    Analyses network traces (.pcap file) based on the test cases checks.
    """
    assert filename
    assert protocol
    assert testcase_id

    if os.path.isfile(filename) is False and os.path.isfile(os.path.join(TMPDIR, filename)):
        filename = os.path.join(TMPDIR, filename)

    logger.info("Analyzing PCAP file %s, for testcase: %s" % (filename, testcase_id))

    if protocol.lower() not in ALLOWED_PROTOCOLS_FOR_ANALYSIS:
        raise NotImplementedError('Protocol %s not among the allowed analysis test suites' % protocol)

    analysis_results = Analyzer('tat_' + protocol.lower()).analyse(filename, testcase_id)
    logger.info('Analysis finished. Got [%s]' % str(analysis_results[1]))

    if output_filename and type(output_filename) is str:
        # save analysis response
        results_to_be_saved = analysis_results[:-1]  # drop the last returned value (exceptions list)
        _dump_json_to_file(json.dumps(results_to_be_saved), output_filename)
        logger.info('Results saved at: %s' % output_filename)

    return analysis_results


def dissect_capture(filename, proto_filter=None, output_filename=None, number_of_frames_to_skip=None):
    """
    Dissects (decodes and converts to string representation) network traces (.pcap file).
    """
    assert filename

    if os.path.isfile(filename) is False and os.path.isfile(os.path.join(TMPDIR, filename)):
        filename = os.path.join(TMPDIR, filename)

    logger.info("PCAP file dissection starts. Filename: %s" % filename)

    proto_matched = None

    if proto_filter:
        # In function of the protocol asked
        proto_matched = get_protocol(proto_filter)
        if proto_matched is None:
            raise Exception('Unknown protocol %s' % proto_filter)

    if number_of_frames_to_skip:
        filename_pcap_filtered = os.path.join(TMPDIR, 'pcap_without_some_skipped_frames.pcap')
        remove_first_frames(
            pcap_filename=filename,
            new_pcap_filename=filename_pcap_filtered,
            number_of_frames_to_skip=number_of_frames_to_skip
        )
        filename = filename_pcap_filtered

    cap = Capture(filename)

    if proto_matched and len(proto_matched) == 1:
        print(proto_matched)
        proto = eval(proto_matched[0]['name'])
        dissection_as_dicts = cap.get_dissection(proto)
        dissection_as_text = cap.get_dissection_simple_format(proto)
        frames_summary = cap.frames
    else:
        dissection_as_dicts = cap.get_dissection()
        dissection_as_text = cap.get_dissection_simple_format()
        frames_summary = cap.frames

    if frames_summary:
        logger.info('PCAP file dissected (filename: %s). Frames summary:\n%s' % (
            filename,
            json.dumps(([repr(c) for c in frames_summary]), indent=4)
        ))
    else:
        logger.info('PCAP file dissected (filename: %s). No frames found.')

    if output_filename and type(output_filename) is str:
        # save dissection response
        _dump_json_to_file(json.dumps(dissection_as_dicts), output_filename)

    return dissection_as_dicts, dissection_as_text


@typecheck
def get_test_cases(
        testcase_id: optional(str) = None,
        verbose: bool = False
) -> OrderedDict:
    """
    Function to get the implemented test cases

    :param testcase_id: The id of the single test case if one wanted
    :param verbose: True if we want a verbose response
    :type testcase_id: str
    :type verbose: bool

    :return: The implemented test cases using doc.f-interop.eu format
    :rtype: OrderedDict
    """

    test_cases = OrderedDict()
    tc_query = [] if not testcase_id else [testcase_id]
    raw_tcs = Analyzer('tat_coap').get_implemented_testcases(
        tc_query,
        verbose
    )

    # Build the clean results list
    for raw_tc in raw_tcs:
        tc_basic = OrderedDict()
        tc_basic['_type'] = 'tc_basic'
        tc_basic['id'] = raw_tc[0]
        tc_basic['objective'] = raw_tc[1]

        tc_implementation = OrderedDict()
        tc_implementation['_type'] = 'tc_implementation'
        tc_implementation['implementation'] = raw_tc[2]

        # Tuple, basic + implementation
        test_cases[raw_tc[0]] = OrderedDict()
        test_cases[raw_tc[0]]['tc_basic'] = tc_basic
        test_cases[raw_tc[0]]['tc_implementation'] = tc_implementation

    # If a single element is asked
    if testcase_id:
        test_cases = test_cases[raw_tcs[0][0]]

    # Return the results
    return test_cases


@typecheck
def get_protocol(
        protocol: optional(str) = None
) -> either(list, type(None)):
    """
    Function to get the protocols protocol(s) info dict

    :param protocol: The name of the protocol
    :type protocol: str

    :return: list of implemented protocols, conditioned to the protocol filter
    :rtype: list of OrderedDict(s)
    """

    # list to return
    answer = []

    # Getter of protocol's classes from dissector
    prot_classes = get_dissectable_protocols()
    logger.debug(str(prot_classes))

    # Build the clean results list
    for prot_class in prot_classes:

        if protocol and protocol.lower() == prot_class.__name__.lower():
            # Prepare the dict for the answer
            prot = OrderedDict()
            prot['_type'] = 'implemented_protocol'
            prot['name'] = prot_class.__name__
            prot['description'] = ''
            return [prot]
        elif protocol is None:
            # Prepare the subdir for the dict-inception (answer)
            prot = OrderedDict()
            prot['_type'] = 'implemented_protocol'
            prot['name'] = prot_class.__name__
            prot['description'] = ''
            answer.append(prot)
        else:
            # not the selected one
            pass

    if answer is None or len(answer) == 0:
        return None
    else:
        return answer


def base64_to_pcap_file(filename, pcap_file_base64):
    """
    Returns number of bytes saved.

    :param filename:
    :param pcap_file_base64:
    :return:
    """
    # save to file
    with open(filename, "wb") as pcap_file:
        nb = pcap_file.write(base64.b64decode(pcap_file_base64))

        return nb


@typecheck
def get_protocols_list() -> list:
    """Function to get the protocols protocols list"""
    return [p.__name__ for p in get_dissectable_protocols()]


def _dump_json_to_file(json_object, filename):
    """

    :param json_object:
    :param filename: filename must include PATH
    :return:
    """

    if '.json' not in filename:
        filename += '.json'

    with open(filename, 'w') as f:
        f.write(json_object)


@typecheck
def _get_token(tok: optional(str) = None):
    """
    Function to get a token, if there's a valid one entered just return it
    otherwise generate a new one

    :param tok: The token if there's already one
    :type tok: str

    :return: A token, the same if there's already one, a new one otherwise
    :rtype: str
    """

    # If the token is already a correct one
    try:
        if all((
                tok,
                type(tok) == str,
                len(tok) == 28,
                base64.urlsafe_b64decode(tok + '=')  # Add '=' only for checking
        )):
            return tok
    except:  # If the decode throw an error => Wrong base64
        pass

    # Generate a token
    token = hashlib.sha1(
        str.encode((
            "%s%04d%s" %
            (
                HASH_PREFIX,
                time.time(),
                HASH_SUFFIX
            )
        ), encoding='utf-8')
    )
    token = base64.urlsafe_b64encode(token.digest()).decode()

    # Remove the '=' at the end of it, it is used by base64 for padding
    return token.replace('=', '')


if __name__ == "__main__":
    proto_class = get_protocol('CoAP')
    # print(str(proto_class))

    proto_class = get_protocol()
    # print(str(proto_class))

    testcases = get_test_cases()
    # print(str(testcases))

    dissection = dissect_capture(
        filename='tests/test_dumps/coap/CoAP_plus_random_UDP_messages.pcap'
    )
    # print(dissection)

    p_list = get_protocols_list()
    print(p_list)
