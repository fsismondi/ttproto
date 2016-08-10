from setuptools import find_packages
from distutils.core import setup

version = "0.0.1"

# TODO update license info

setup(
    name='ttproto',
    version=version,
    url='https://www.irisa.fr/tipi/wiki/doku.php/testing_tool_prototype',
    author='Universite de Rennes 1 / INRIA',
    maintainer='Federico Sismondi',
    maintainer_email='federico.sismondi@inria.fr',
    description=('ttproto is an experimental tool for implementing testing'
                 'tools, for conformance and interoperability testing mainly.'),
    license='TODO',
    #packages=find_packages(exclude=['tests', 'tests.*']),
   )
