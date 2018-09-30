=======================
Contributing to ttproto
=======================

Thank you for considering contributing to ttproto!


.. contents:: Table of content

.. note:: TODO list:
    - Put doc about how to dev a lib for a protocol
    - Document conformance test suite
    - Put doc about Templates if needed (optional)
    - Document amqp and http interface of ttproto


Git workflow - Merge request guidelines
=======================================


If you can, please submit a merge request with the fix or improvements
including tests. If you don't know how to fix the issue but can write a test
that exposes the issue we will accept that as well. In general bug fixes that
include a regression test are merged quickly while new features without proper
tests are least likely to receive timely feedback. The workflow to make a merge
request is as follows:


.. [#] Fork the project into your personal space on gitlab
.. [#] Create a feature branch, branch away from master (if it's a fix) or develop (if it's a new feature or doc)
.. [#] Write tests, code and/or doc
.. [#] If you have multiple commits please combine them into a few logically organized commits by squashing them
.. [#] Push the commit(s) to your fork
.. [#] Submit a merge request (MR) to the master branch / develop branch (depending if it's a fix or new feature)

Some other comments:

.. [#] The MR title should describe the change you want to make
.. [#] The MR description should give a motive for your change and the method you used to achieve it.
.. [#] If you are proposing core/substantial changes to the tools please create an issue first to discuss it beforehand.
.. [#] Mention the issue(s) your merge request solves, using the Solves #XXX or Closes #XXX syntax.
.. [#] Please keep the change in a single MR as small as possible.
.. [#] For examples of feedback on merge requests please look at already closed merge requests.
.. [#] Merging will be done by main maintainer after reviewing the changes.

When having your code reviewed and when reviewing merge requests please take the
code review guidelines into account.


Contributing with a new Testing Tool
====================================

The main objective of this document is to provide guidelines for contributing to ttproto with new
suites / analysis tools using ttproto APIs and libraries. This document contains two parts;
(1) guidelines on how to provide a **conformance** test suite (TBD) and (2) guidelines on how to provide
an **interoperability** testsuite / test analyzer tool.
A conformance test suite testing a protocol **foo** in the ttproto environment is named **TS_foo**,
and an interoperability test suite, testing a protocol **bar**, is named **TAT_bar**.
TAT stands for test analysis tool. Interoperability TAT in ttproto are
tools which analyze the exchanged frames in a interop test **post mortem**,
meaning after the test has been executed.
ttproto uses pcaps (not pcap-ng) as input for analysing the exchanged frames during
an interop test. This makes ttproto an easier tool to integrate into other systems
given it's passive, non intrusive approach for running tests.


Interoperability test suite / TAT
=================================
Here we will see how to implement an interoperability test suite using ttproto's
tool. You can find two examples of this type of test suite into **tat_coap**
and **tat_6lowpan** subdirectories of **ttproto**.

Firstly, lets provide an example of what a test case implementation looks like:


.. code-block:: python

    from ..common import *
    class TD_COAP_CORE_01 (CoAPTestCase):
        """
    ---
    TD_COAP_CORE_01:
        cfg: CoAP_CFG_BASIC
        obj: Perform GET transaction(CON mode)
        pre: Server offers the resource /test with resource content
            is not empty that handles GET with an arbitrary payload
        ref: '[COAP] 5.8.1, 1.2, 2.1, 2.2, 3.1'
        seq:
        -   s:
            - 'Client is requested to send a GET request with:'
            -   - Type = 0(CON)
                - Code = 1(GET)
        -   c:
            - 'The request sent by the client contains:'
            -   - Type=0 and Code=1
                - "Client-generated Message ID(\u2794 CMID)"
                - "Client-generated Token(\u2794 CTOK)"
                - Uri-Path option "test"
        -   c:
            - 'Server sends response containing:'
            -   - Code = 2.05(Content)
                - Message ID = CMID, Token = CTOK
                - Content-format option
                - Non-empty Payload
        -   v: Client displays the received information
        """

        @classmethod
        @typecheck
        def get_stimulis(cls) -> list_of(Value):
            """
            Get the stimulis of this test case. This has to be be implemented into
            each test cases class.

            :return: The stimulis of this TC
                :rtype: [Value]
                """
                return [CoAP(code='get')]

            def run(self):
                self.match(
                    'client',
                    CoAP(type='con', code='get', opt=self.uri('/test'))
                )
                CMID = self.coap['mid']
                CTOK = self.coap['tok']

                self.next()

                if self.match(
                    'server',
                    CoAP(code=2.05, mid=CMID, tok=CTOK, pl=Not(b''))
                ):
                    self.match(
                        'server',
                        CoAP(opt=Opt(CoAPOptionContentFormat())),
                        'fail'
                    )


Note that the implementation of the test case it's quite simple and short.
There are two main "directives" used during a testcase, those are
**self.next()** and **self.match**:

    - **self** points and iterates over the frames of the pcap capture (after the pre-filter phase, but let's leave that discussion for later..).

    - **self.next()** iterates over the frames

    - **self.match()** we evaluate the CHECKs described in the test description.

Also, note that **self.match()** takes as parameter (1) the node which is associated to
the current frame to be evaluated (the association can be for example the
node that sent the frame) but more importantly (2) the template to match,
e.g. CoAP(opt=Opt(CoAPOptionContentFormat()).

This is one of the strong points of ttproto, the simplicity to generate templates.
We will came later on into this discussion.


Matching operation examples
===========================

Now let's show a couple of examples to undestand match operation behaviour:

in tests/test_dumps/coap_core/TD_COAP_CORE_01_PASS.pcap you can find an example of exchanges
expected while performing a GET transaction in CON mode, which corresponds to TD_COAP_CORE_01.

basically::

    "<Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON 43521] GET /test>",
    "<Frame   2: [127.0.0.1 -> 127.0.0.1] CoAP [ACK 43521] 2.05 Content >"

now I'll describe the expexted behaviours of the match operation by using the following snippet
and ttproto/tat_coap/TD_COAP_CORE_01.py test case.

.. code-block:: python

    from os import getcwd, path

    analyzer = Analyzer('tat_coap')
    params = './tests/test_dumps/coap_core/TD_COAP_CORE_01_pass.pcap', 'TD_COAP_CORE_01'
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


Let's use as example the testcase TD_COAP_CORE_01,

where we check that client's message matches the following template:

    CoAP(type='con', code='get', opt=self.uri('/test')

and under the circumstance where the server response is ok (2.05 code), that it correlates to the request(CTOK),
and that it returns a non empty payload: CoAP(code=2.05, mid=CMID, tok=CTOK, pl=Not(b''))
then if server message  doesnt provide a CoAPOptionContentFormat the test will fail:

    self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat())), 'fail')

note that if any of the two first operations dont match the expected, then the test will return an 'inconclusive'
verdict.

.. code-block:: python

    def run(self):
        self.match('client', CoAP(type='con', code='get', opt=self.uri('/test')))
        CMID = self.coap['mid']
        CTOK = self.coap['tok']

        self.next()

        if self.match('server', CoAP(code=2.05, mid=CMID, tok=CTOK, pl=Not(b'')), None):
            self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat())), 'fail')




returns::

    ##### TC name
    TD_COAP_CORE_01
    #####
    ##### Verdict given
    pass
    #####
    ##### Review frames
    []
    #####
    ##### Text
    <Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON 43521] GET /test>
      [ pass ] <Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON 43521] GET /test> Match: CoAP(type=0, code=1)
    <Frame   2: [127.0.0.1 -> 127.0.0.1] CoAP [ACK 43521] 2.05 Content >
      [ pass ] <Frame   2: [127.0.0.1 -> 127.0.0.1] CoAP [ACK 43521] 2.05 Content > Match: CoAP(opt=Opt(CoAPOptionContentFormat()))

    ##### Partial verdicts
    ('pass', '<Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON 43521] GET /test> Match: CoAP(type=0, code=1)')
    ('pass', '<Frame   2: [127.0.0.1 -> 127.0.0.1] CoAP [ACK 43521] 2.05 Content > Match: CoAP(opt=Opt(CoAPOptionContentFormat()))')
    #####
    ##### Exceptions
    #####

the output here says that the testcase has **passed**, and the essential information is described in the partial verdicts::

    ('pass', '<Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON 43521] GET /test> Match: CoAP(type=0, code=1)')
    ('pass', '<Frame   2: [127.0.0.1 -> 127.0.0.1] CoAP [ACK 43521] 2.05 Content > Match: CoAP(opt=Opt(CoAPOptionContentFormat()))')

we can add some extra requirements on the 3rd match operation asking that response must include a CoAP Option Block:

.. code-block:: python

    if self.match('server', CoAP(code=2.05, mid=CMID, tok=CTOK, pl=Not(b'')), None):
        self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat(), CoAPOptionBlock())), 'fail')


which returns a **fail** when run on the previously described PCAP file as the server's response doesnt include
this CoAP option::

    ##### TC name
    TD_COAP_CORE_01
    #####
    ##### Verdict given
    fail
    #####
    ##### Review frames
    [2]
    #####
    ##### Text
    <Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON 43521] GET /test>
      [ pass ] <Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON 43521] GET /test> Match: CoAP(type=0, code=1)
    <Frame   2: [127.0.0.1 -> 127.0.0.1] CoAP [ACK 43521] 2.05 Content >
      [ fail ]  Mismatch: CoAP(opt=Opt(CoAPOptionBlock(), CoAPOptionContentFormat()))
                 CoAP.opt: CoAPOptMismatch
                     got:
                     expected: CoAPOptionBlock()

    ##### Partial verdicts
    ('pass', '<Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON 43521] GET /test> Match: CoAP(type=0, code=1)')
    ('fail', ' Mismatch: CoAP(opt=Opt(CoAPOptionBlock(), CoAPOptionContentFormat()))')
    #####
    ##### Exceptions
    #####


We can also override the default **fail** messages using:

.. code-block:: python

        if self.match('server', CoAP(code=2.05, mid=CMID, tok=CTOK, pl=Not(b'')), None):
            self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat(), CoAPOptionBlock())), 'fail', "Missing CoAP options")

returns::

    ##### TC name
    TD_COAP_CORE_01
    #####
    ##### Verdict given
    fail
    #####
    ##### Review frames
    [2]
    #####
    ##### Text
    <Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON 43521] GET /test>
      [ pass ] <Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON 43521] GET /test> Match: CoAP(type=0, code=1)
    <Frame   2: [127.0.0.1 -> 127.0.0.1] CoAP [ACK 43521] 2.05 Content >
      [ fail ] Missing CoAP options
                 CoAP.opt: CoAPOptMismatch
                     got:
                     expected: CoAPOptionBlock()

    ##### Partial verdicts
    ('pass', '<Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON 43521] GET /test> Match: CoAP(type=0, code=1)')
    ('fail', 'Missing CoAP options')
    #####
    ##### Exceptions
    #####

Testcase Class and subclasses
=============================

Now, let's describe the different libraries that are provided and the
elements that the contributor has to provide,for writing his/her TAT, or
test suite.

Here is a scheme to describe the global structure of an interoperability test
suite, with the purpose and functions at each level described beside it::

 +----------+                    | Test case super class, nothing to change
 | TestCase |                    | here, the following functions are provided:
 +----------+                    |
      /\                         | - match()           - log()
      ||                         | - next()            - set_verdict()
      ||                         | - run_test_case()
      ||                         |______________________________________________
 +------------------+            | The common TestCase class, its purpose is to
 | ProtocolTestCase |            | define functions that can be used in every
 +------------------+            | test cases. It can also provide utility
      /\                         | functions to each test case instance
      ||                         |
      ||                         | - get_protocol()
      ||============= \          | - preprocess()
      ||             ||          | - get_test_purpose()
      ||             ||          |______________________________________________
 +-----------+   +-----------+   | The test case itself, written from a test
 | TD_..._01 |   | TD_..._02 |   | description and providing the actual run
 +-----------+   +-----------+   |
                                 | - get_nodes_identification_templates()
                                 | - get_stimulis()
                                 | - run()


Common module
-------------
Into the **TAT_foo** directory, create a **common.py** file which will correspond to
the common test case module for this test environment. It will define every
needed functions and utilities for the TDs implementation.


Required module imports
~~~~~~~~~~~~~~~~~~~~~~~
This module will take care of importing every needed libraries and classes from
*ttproto*, here is a list of the modules that can interest us::

  - ttproto.core.analyzer
  - ttproto.core.dissector
  - ttproto.core.templates
  - ttproto.core.lib.all


Common TestCase class
~~~~~~~~~~~~~~~~~~~~~
This module also have to contain a **TestCase inherited class** named after the
test environment used that will be our **common TestCase class** (CF scheme).
The purpose of this module is to provide **utility functions** that are common to
all the test cases that will be launched associated to this test environment.


Common functions to implement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Into this common *TestCase* class, here are the functions that have to be
defined:

get_protocol()
    Provide the protocol that concerns the test case. This will be used in the
    verification of frame values.

    - *classmethod*
    - No parameter
    - Returns a protocol class (which is a subclass of *Value*)

preprocess()
    Preprocess a Capture object from which it will generate the conversations on
    which the test case will be run.

    - Takes a *Capture* object as parameter
    - Returns a tuple containing the conversations and the ignored frames

get_test_purpose()
    Provide the test purpose of this test case.

    - *classmethod*
    - No parameter
    - Returns the test purpose as a string
    - *Can be implemented manually into each test case, giving the raw text*
    - *If the documentation of test cases follows the one explained into
      Styleguides topic, no need to reimplement this function*


Test Description implementation
-------------------------------
The TD's implementation are the actual test case that will be run.


Required module imports
~~~~~~~~~~~~~~~~~~~~~~~
The TD's implementation should only **import the elements from common module**
which is used like an entry point for accessing to *ttproto*'s libraries because
most of the time, the elements that we import from *ttproto* will be used in
many test cases and not only one.


Test description's implementation class
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Each TD's implementation should be put into a module named following the
**unique id** of the TD in lower case and its class name should be the same in
upper case. Each class should **inherit the common test case** one in order to
retrieve from it the utility functions or *TestCase*'s not implemented ones.

By the way, the documentation of the TD's implementation class **should follow
the syntax** described in the `Test Case Documentation Styleguide`_.


Test description's implementation function to implement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Into this TD's implementation class, here are the functions that have to be
defined:

get_nodes_identification_patterns()
    Provide the list of Nodes taking part in this test case.

    - *classmethod*
    - No parameter
    - Returns a list of *Node* objects
    - *Can be defined into common class if generic*

get_stimulis()
    Provide list of stimulis, in the order in which we should encounter them.

    - *classmethod*
    - No parameter
    - Returns a list of *Value* objects.

run()
    The actual execution of the test case as specified in the TD.
    We will see afterward what can be used to write the run() method.

    - No parameter
    - Returns nothing


TestCase library class
----------------------
The *TestCase* class already offers many tools and utilities to run an actual
test case. Here what you can use for the *run()* method of TD's implementations.

You can access to its functions and variables directly from the common test case
or the TD's implementation by calling to themselves as they both inherits the
*TestCase* class.


Testcase attributes
~~~~~~~~~~~~~~~~~~~
Here are the variables provided by the *TestCase* class for each instance of
classes inheriting it:

_verdict
    A *Verdict* object which purpose is to store the current verdict and update
    it when needed, following a priority rule.

_capture
    The *Capture* object that stores all the frames passed to the execution.
    Frames are accessible from *frames* variable of this object, but they are
    raw frames and should be filtered using the *preprocess()* method.

_conversations
    The conversations that are a list of *Conversation* objects generated from
    preprocessing the capture passed to the test case.

_ignore_frames
    The frames that were ignored after the preprocessing.

.. note::
    In fact, there more accessible variables than that but they are used\
    internally into provided utility functions. Even if they are accessible,\
    normally you will never have to use them and if so, it is not recommended\
    at all to access them in writing.


Class provided
~~~~~~~~~~~~~~
There is only a single intern class provided by *TestCase* which is named
**Stop** and inherits *Exception*. It's an exception that is thrown to abort the
current running test case.


Functions provided
~~~~~~~~~~~~~~~~~~
Here are the functions provided by the *TestCase* class, for each instance of
classes inheriting it, which will allow you to execute the actual *run()*
method:

\__init__()
    The initialisation function for each test case to initialize itself

    - Takes a *Capture* object which corresponds to the recorded communications
      to analyze
    - Returns nothing

run_test_case()
    The function to actually run the test case after it is initilized. It will
    call the *run()* method of the TD's implementation as many times that there
    are conversations occurences into the recorded communications passed.

    - Takes no parameter
    - Returns a tuple containing the following information:
        - The **verdict** as a *string*
        - The list of the **result concerned frames** as *list of int*
        - **Extra informations** as a *string*
        - **The exceptions** that occured as a *list of tuple* formatted like:
            - The **exception's class** as a *type*
            - The **exception** object itself as an *Exception*
            - The **traceback** of when the it has occured as a *traceback* object

match()
    Allow you to check that the current frame's format corresponds to the one
    provided in the test description.

    - Takes 4 parameters that are the following:
        - The name of the **sending node** as a *string*
        - The **template** to which we will compare the current frame as *Value*
        - The **verdict** to assign in case of operation mismatch as an *optional string*
        - The **message** to assign in case of operation mismatch as an *optional string*
    - Returns *True* if it matches, *False* if not

next()
    Allow you to parse the list of frames by getting to the next one.

    - Takes one parameters which is a *boolean* named **optional** to know if
      the next frame is optional or not. If not and no following frame, error is
      thrown.
    - Returns nothing

log()
    Allow you to log anything. *Can be reimplemented in lower levels*

    - Takes a parameter that can be anything
    - Returns nothing

set_verdict()
    Update the verdict of the current execution. A priority is put on the
    verdicts so it will really update only when the new one has higher priority.

    - Takes 2 parameters that are the following:
      - The **new verdict** to put as a *string*
      - The **msg** associated to it as a *string*
    - Returns nothing

get_test_purpose()
    Allow you to get the test purpose of a *TestCase*. This is a default one
    that will only work if your *TestCase* class documentation uses the format
    described into `Test Case Documentation Styleguide`_.

    - *classmethod*
    - Takes no parameter
    - Returns a *string* representation of the **test purpose**


How to write the whole test suite
=================================

.. note:: Put the way to define the libraries needed for packet decoding smwhere


Creating the test environment
-----------------------------
The first task to do this is to create the test environment.

You have to create a folder into ttproto with name defined as **tat_[test_env]**
. We took as convention that the **test_env** is the name of the protocol.
Now that we have the test env set, create a **testcases** directory inside this
one, we will put test cases definition into it later.


Creating the common module
--------------------------
Into this directory, define the **common module** from the instructions provided
in `Common module`_ part and into it, define the **common test case class**
from the instructions provided in the `Common module`_ part without forgetting
defining what has to be implemented at this level.

If some own utility elements like functions, variables or classes has to be
defined, they should be defined into this module or at least imported from it.


Creating a test case
--------------------
In the **testcases** directory, you can create a test case by following the
instructions provided at the `Test Description implementation`_ part. Now that
this is done, we will see how to write the TD's implementation.


Test configuration
~~~~~~~~~~~~~~~~~~
We will start by providing the test configuration, you have two functions for
this:

**get_stimulis()** will allow you to provide the stimulis of the test case, you
can get them from the test description and you have to put them into the list in
the same order as they should appear. A stimuli here consist into a *Template*
object.

**get_nodes_identification_patterns()** will allow you to provide the node
configuration of the test case. It consists into a list of *Node* objects which
just contains the information about the **name** of the node and its
**template**.


Run method
~~~~~~~~~~
Now, you can provide the actual run of the test by writting the *run()* method.
You can look at the `Functions provided`_ section for every usefull functions
but the main ones that you need are **match()** for checking, **log()** if you
want to log messages and **next()** for going from one frame to another.



Conformance test suite
======================

**TBD**


Styleguides
===========


Python Styleguide
-----------------
All Python code should respect the PEP8_ Styleguide for more readability.


Test Case Documentation Styleguide
----------------------------------
All test case documentation should be written into Yaml_, following this
format::

  """
  ---
  TestCaseUniqueId:
      cfg: Configuration of this test case
      not: Some notes (can be multiple)
      obj: Purpose of the test case, also named objective
      pre: Prerequisite for this test case
      ref: RFC's references
      seq:
          -   s: This describes a stimulis
          -   s:
              - This is a multiple lines stimuli
              -   - First part of the stimuli
                  - Second and last one
          -   c: This describres a check
          -   c:
              - 'This is a check on multiple lines:'
              -   - First thing to check
                  - Second one
                  - Third and last one
          -   f: This is a feature
          -   f:
              - This is a multiline feature without colon
              -   - First part of the feature
                  - Second and last part
          -   v: This is a verify
          -   v:
              - 'This is a verify on multiple lines:'
              -   - First thing to verify
                  - Second and last one
  """


.. warning::
    There can be some problems with special characters, mostly with ':', '\\' \
    or '/' that can occur in some test descriptions, and with non-ascii\
    characters.

    For the first case, use quotes and for the second, use special characters
    like \\u2794 for example.


.. _PEP8: https://www.python.org/dev/peps/pep-0008/
.. _Yaml: http://www.yaml.org/spec/1.2/spec.html
