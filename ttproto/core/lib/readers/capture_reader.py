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


from ttproto.core.typecheck import *


class CaptureReader:
    """
    The CaptureReader interface class which will allow us to read capture files
    """

    @typecheck
    def __init__(self, file: str):
        """
        Initialize the reader with the corresponding file

        :param file: The path to the file to read
        :type file: str
        """
        raise NotImplementedError()

    def __iter__(self):
        """
        The only thing that the reader need is that it sould be iterable. Each
        returned element should be a tuple of
            - Timestamp represented as a float
            - The Message object associated to the frame
            - An Exception if one occured, None if everything went fine
        """
        raise NotImplementedError()
