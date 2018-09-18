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

import yaml

from ttproto.core.exceptions import ReaderError
from ttproto.core.typecheck import *


class YamlReader:
    """
    Reader class for yaml file or text
    """

    # Some class constants mainly for dumping format
    YAML_LINE_WIDTH = 70
    INDENTATION_SPACES_LENGTH = 4

    @typecheck
    def __init__(self, text: str, raw_text: bool = False):
        """
        Initialize yaml reader with the text can be a raw text or a filename

        :param text: The filename if file or a raw yaml text
        :param raw_text: True if raw text, default False for filename
        :type text: str
        :type raw_text: bool
        """
        self.__text = text
        self.__raw_text = raw_text
        self._yaml_as_dict = None
        self._flat_yaml = None

    @typecheck
    def __process_dict(self) -> dict:
        """
        Process the dictionary value of this yaml object

        :return: The python dict representation of this yaml object
        :rtype: dict
        """
        try:

            # If a raw text
            if self.__raw_text:
                return yaml.load(self.__text)

            # If a file
            else:
                with open(self.__text, 'r') as yaml_file:
                    return yaml.load(yaml_file)

        # If yaml error during decoding
        except yaml.YAMLError as ye:
            raise ReaderError(
                "YamlReader was unable to open and parse the %s file"
                %
                self.__text
            ) from ye

    @property
    def as_dict(self):
        """
        Singleton method to process the dictionary value of this yaml object

        :return: The python dict representation of this yaml object
        :rtype: dict
        """
        if not self._yaml_as_dict:
            self._yaml_as_dict = self.__process_dict()
        return self._yaml_as_dict

    @typecheck
    def __process_flat(self) -> str:
        """
        Process the flat value of this yaml object

        :return: The yaml flat representation
        :rtype: str
        """
        try:

            # If a raw text
            if self.__raw_text:
                to_dump = self.__text

            # If a file
            else:
                with open(self.__text, 'r') as yaml_file:
                    to_dump = yaml.load(yaml_file)

            # Return the loaded yaml file
            return yaml.dump(
                    to_dump,
                    width=self.YAML_LINE_WIDTH,
                    indent=self.INDENTATION_SPACES_LENGTH,
                    default_flow_style=False
                )

        # If yaml error during decoding
        except yaml.YAMLError as ye:
            raise ReaderError(
                "YamlReader was unable to flat the %s file"
                %
                self.__text
            ) from ye

    @property
    def as_flat_yaml(self):
        """
        Singleton method to process the flat value of this yaml object

        :return: The yaml flat representation
        :rtype: text
        """
        if not self._flat_yaml:
            self._flat_yaml = self.__process_flat()
        return self._flat_yaml
