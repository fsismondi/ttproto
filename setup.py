#! /usr/bin/env python
# -*- coding:utf-8 -*-

import os
from setuptools import setup, find_packages

PACKAGE = 'ttproto'
LICENSE = 'CeCILL'


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


CLASSIFIERS = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Science/Research",
    "Intended Audience :: Developers",
    "Programming Language :: Python",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.5",
    "Programming Language :: Python :: 3.6",
    "Topic :: Internet",
    "Topic :: Software Development :: Testing",
    "Topic :: Scientific/Engineering",
    "Operating System :: POSIX",
    "Operating System :: Unix",
    "Operating System :: MacOS"
]

with open('README.md', 'r') as fh:
    long_description = fh.read()

setup(
    name=PACKAGE,
    version=get_version(PACKAGE),
    url='https://www.irisa.fr/tipi/wiki/doku.php/testing_tool_prototype',
    author='Univ Rennes / INRIA',
    maintainer='Federico Sismondi',
    maintainer_email='federico.sismondi@inria.fr',
    description=('ttproto is an experimental tool for implementing testing'
                 'tools, for conformance and interoperability testing mainly.'),
    license=LICENSE,
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=find_packages(),
    classifiers=CLASSIFIERS,
    include_package_data=True,  # see MANIFEST.in
    install_requires=[
        'pyyaml',
        'requests',
        'pika',
    ],

)
