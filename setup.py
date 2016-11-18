#! /usr/bin/env python
# -*- coding:utf-8 -*-

import os
from setuptools import setup, find_packages

PACKAGE = 'ttproto'
LICENSE = 'CeCILL'
SCRIPTS = ['ttproto']


# Read version without importing for coverage issues
def get_version(package):
    """ Extract package version without importing file

    Importing module alter coverage results and may import some non-installed
    dependencies. So read the file directly

    Inspired from pep8 setup.py
    """
    with open(os.path.join(package, '__init__.py')) as init_fd:
        for line in init_fd:
            if line.startswith('__version__'):
                return eval(line.split('=')[-1])  # pylint:disable=eval-used


setup(
    name=PACKAGE,
    version=get_version(PACKAGE),
    url='https://www.irisa.fr/tipi/wiki/doku.php/testing_tool_prototype',
    author='Universite de Rennes 1 / INRIA',
    maintainer='Federico Sismondi',
    maintainer_email='federico.sismondi@inria.fr',
    description=('ttproto is an experimental tool for implementing testing'
                 'tools, for conformance and interoperability testing mainly.'),
    license=LICENSE,
    packages=find_packages(),
    scripts=SCRIPTS,
    classifiers=['Development Status :: 2 - Pre-Alpha',
                 'Programming Language :: Python :: 2'],
    install_requires=['yaml','requests'],
)
