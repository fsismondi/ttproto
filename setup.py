from setuptools import find_packages

version = __import__('ttproto').get_version()

# TODO update license info

setup(
    name='ttproto ',
    version=version,
    url='https://www.irisa.fr/tipi/wiki/doku.php/testing_tool_prototype',
    author='Universite de Rennes 1 / INRIA',
    author_email='t3devkit@irisa.fr',
    maintainer='Federico Sismondi',
    maintainer_email='federico.sismondi@irisa.fr',
    description=('ttproto is an experimental tool for implementing testing'
                 'tools, for conformance and interoperability testing.'),
    license='TODO',
    packages=find_packages(exclude=['tests', 'tests.*']),
   )
