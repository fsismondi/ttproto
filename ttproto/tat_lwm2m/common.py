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

from .templates import *
from ttproto.core.analyzer import TestCase, is_protocol, Node, Conversation, Capture
from ttproto.core.dissector import Frame
from ttproto.core.templates import All, Not, Any, Length
from ttproto.core.typecheck import *
from ttproto.core.lib.all import *
from urllib import parse
from ttproto.core.exceptions import Error
from ttproto.tat_coap.common import CoAPTestCase, NoStimuliFoundForTestcase, FilterError

from xml.etree import ElementTree
import logging
import requests
import json
import sys

# CoAP constants
RESPONSE_TIMEOUT = 2
RESPONSE_RANDOM_FACTOR = 1.5
MAX_RETRANSMIT = 4
MAX_TIMEOUT = 10 + round(
    (RESPONSE_TIMEOUT * RESPONSE_RANDOM_FACTOR) * 2 ** MAX_RETRANSMIT
)


def validate(jsond, objectid):
    logging.info("ObjectID: " + objectid)
    jsondata = jsond[2:]
    jsondata = jsondata[:-1]
    jsondata = json.loads(jsondata)
    # logging.info json.dumps(jsondata, sort_keys=True,indent=4, separators=(',', ': '))

    url = 'http://www.openmobilealliance.org/api/lwm2m/v1/Object?ObjectID=' + objectid;
    logging.info("Registry url: " + url)
    r = requests.get(url)
    # logging.info json.dumps(r.json(), sort_keys=True,indent=4, separators=(',', ': '))
    j = r.json()
    logging.info("ObjectLink: " + j[0]["ObjectLink"])
    r2 = requests.get(j[0]["ObjectLink"])
    # logging.info r2.content
    root = ElementTree.fromstring(r2.content)
    
    result = []
    validation = "pass"
    message = "["
    for item in root.iter('Item'):
        for child in item:
            if (child.text == "Mandatory"):
                if (item.find("Operations").text != "E"):
                    logging.info("ResourceID: " + item.get("ID"))
                    logging.info("Name: " + str(item.find("Name").text))
                    logging.info("Type: " + str(item.find("Type").text))
                    logging.info("Operations: " + str(item.find("Operations").text))
                    logging.info("MultipleInstances: " + str(item.find("MultipleInstances").text))
                    for attrs in jsondata['e']:
                        itemuri = item.get("ID");
                        if (item.find("MultipleInstances").text == "Multiple"):
                            itemuri = itemuri + "/0";
                        if attrs['n'] == itemuri:
                            n = attrs['n']
                            logging.info("Found!")
                            message+="{"+str(item.find("Name").text)+" : validated}"
                            break
                    else:
                        validation = "fail"
                        logging.info('Not found!')
                        message+="{"+str(item.find("Name").text)+" : not validated}"
    
    message += "]"
    result.append(validation)
    result.append(message)
    logging.info("Validation: " + result[0])
    return result


if __name__ == "__main__":
    pass
