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

"""The core.control module provides the function for handling the testcase
definition and for their execution.
"""


import collections, gc, signal, threading, time, traceback, types, os

from	ttproto.core.typecheck	import *
from	ttproto.core		import clock, data, exceptions, logger, snapshot

__all__ = [
	'all_testcases',
	'Verdict',
	'VerdictValue',
	'VerdictSummary',
	'init_verdict',
	'set_verdict',
	'get_verdict',
	'Config',
	'Testcase',
	'EventTestcaseStarted',
	'EventTestcaseTerminated',
	'EventTestcaseRuntimeError',
	'TestSession',
	'EventTestSessionStarted',
	'EventTestSessionAborted',
	'EventTestSessionError',
	'EventTestSessionTerminated',
	'EventSetVerdict',
	'testcase',
	'run_all_testcases',
	'stop',
	'SUTAction',
	'SUTActionFailed',
	'SUTActionManual',
]


all_testcases = []

__thread_local = threading.local()

class Verdict:
	"""A class handling the verdict for a test case

	Known verdict values are:
	 - "none"	no verdict set yet
	 - "pass"	the NUT fulfilled the test purpose
	 - "inconclusive"	the NUT did not fulfill the test purpose but did not display bad behaviour
	 - "fail"	the NUT did not fulfill the test purpose and displayed a bad behaviour
	 - "aborted"	the test execution was aborted by the user
	 - "error"	a runtime error occured during the test


	At initialisation time, the verdict is set to None. Then it can be updated one or
	multiple times, either explicitely calling set_verdict() or implicitely if an
	unhandled exception is caught by the control module (error verdict) or if the user
	interrupts the test manually (aborted verdict).

	Each value listed above has precedence over the previous ones. This means
	that when a verdict is updated, the resulting verdict is changed only if
	the new verdict is worse than the previous one.
	"""

	__values = ("none", "pass", "inconclusive", "fail", "aborted", "error")

	def __init__ (self, initial_value = None):
		self.__value = 0
		if initial_value is not None:
			self.update (initial_value)

	@typecheck
	def update (self, new_verdict:str , message: str = ""):
		"""Update the verdict"""

		assert new_verdict in self.__values

		new_value = self.__values.index(new_verdict)
		if new_value > self.__value:
			self.__value = new_value

		logger.log_event (EventSetVerdict (new_verdict, message))

	@classmethod
	def values (cls):
		"""List the known verdict values"""
		return cls.__values

	def get_value (self):
		"""Get the value of the verdict"""
		return self.__values [self.__value]

	def __str__ (self):
		return self.__values [self.__value]

VerdictValue = str

class VerdictSummary:
	"""A class holding the list of the testcases that are run, with their verdict"""
	def __init__ (self):
		self.__summary = collections.Counter()
		for k in Verdict.values():
			self.__summary[k] = 0

		self.__testcase_results = []

	@typecheck
	def update (self, testcase, verdict: VerdictValue):
		"""Update the summary with a new test result"""
		assert isinstance (testcase, Testcase)

		self.__summary.update ((verdict,))
		self.__testcase_results.append ((testcase, verdict))

	def count (self):
		"""return the number of testcase that were run"""
		nb = 0
		for v in self.__summary.values():
			nb += v
		return nb

	def __iter__ (self):
		"""Return an iterator of an histogram of the verdict values

		The iterator yields a set of tuples “(verdict, count)” indicating
		the occurence of each verdict.
		"""
		for v in Verdict.values():
			yield v, self.__summary[v]

	def __str__ (self):
		return ", ".join ("%s: %d" % (k, self.__summary[k]) for k in Verdict.values())

	def testcases (self):
		"""Return an iterator on the run testcases with their verdict

		The iterator yields a set of tuples “(testcase, verdict)”
		"""
		return iter (self.__testcase_results)

def init_verdict():
	"""Initialise the verdict of the current thread"""
	threading.current_thread().verdict = Verdict()

# TODO: log the message
def set_verdict(new_verdict, message = ""):
	"""Update the verdict of the current thread"""
	threading.current_thread().verdict.update (new_verdict)

def get_verdict():
	"""Get the verdict of the current thread"""
	return threading.current_thread().verdict.get_value()


class Config:
	"""A class for parametering the test cases and for setting up the test configuration.

	A configuration can contain one on more named parameters that are
	stored in a dict and used as actual parameters when running the the
	testcases.

	The Config class can also be used to handle test setup and cleanup
	(through the __enter__ and __exit__ functions).

	Example:
		class TestConfig (Config):
			pass

		@testcase (TestConfig)
		def TC_config_test (A, B, C):
			print (A, B, C)
			set_verdict ("pass")



		my_cfg = TestConfig ({"A": 12, "B": 48})

		my_cfg["B"] = 27
		my_cfg["C"] = 137

		run_all_testcases ({TestConfig: my_cfg})

	Output:
		[795.5007] Testcase Started:    TC_config_test
		12 27 137
		[795.5008] Testcase Terminated: TC_config_test --> pass
	"""
	#TODO: use a metaclass to do some typechecking on the parameters and on the testcase parameters (like in LogEvents)

	@typecheck
	def __init__ (self, dict_init_value: iterable = ()):
		"""Initialise the configuration

		The dict_init_value, if provided contains the intialisation
		value for the dictionnary of parameters.
		"""
		self.__params = dict (dict_init_value)

	def run (self, testcase, func, **kw):
		"""Run a testcase main function using this configuration

		This function enter the self context (“with self:”) and calls
		the function 'func' using the parameters provided in **kw.
		Before calling the function, it does some introspection in
		'func' to determine if this function requires other parameters
		(not provided by **kw), to fill them with the parameters set in
		the internal dict of this Config object (or raise an error if
		the parameter is unknown).

		In case of runtime error (unhandled exception) the function
		catches the exception and generates an
		EventTestcaseRuntimeError log event describing the error.
		"""
		try:
			stage = 0
			with self:
				stage = 1
				for i in range (0, func.__code__.co_argcount):
					name = func.__code__.co_varnames[i]

					if name not in kw:
						if name in self.__params:
							kw[name] = self.__params[name]
						else:
							raise exceptions.Error ("Missing configuration parameter '%s'" % name)
				stage = 2
				func (**kw)
				stage = 3

		except exceptions.UserInterrupt:
			raise

		except exceptions.TerminateTestcase:
			pass

		except Exception as e:
			if stage < 2:
				msg = "configuration setup failed (%s)"
			elif stage > 2:
				msg = "configuration cleanup failed (%s)"
			else:
				msg = "%s"

			logger.log_event (EventTestcaseRuntimeError (testcase, msg % str(e), traceback.format_exc()))
			set_verdict("error")

	def __setitem__ (self, key, value):
		"""Set one config parameter"""
		self.__params[key] = value

	def __getitem__ (self, key):
		"""Get one config parameter"""
		return self.__params[key]

	def __enter__ (self):
		"""Enter this config context"""
		pass

	def __exit__ (self, a, b, c):
		"""Leav this config context"""
		pass


class Testcase (snapshot.EventSource):
	"""A class representing a testcase

	A testcase is associated to a function (the entry point of the
	testcase) and a type of configuration (subclass of Config) that must be
	provided at runtime so that the test can run properly.

	Testcase objects are usually not instantiated directly, but with the
	help @testcase decorator function.
	"""

	def __init__ (self, func, config_type: type = Config):
		"""Initialise the testcase

		- 'func' is the main function of the testcase
		- 'config_type' is the type of config that must be provided at
		  runtime so that the testcase can run properly (by default
		  Config is used)

		The name of the testcase (__name__ attribute is initialised
		from the name of the function 'func').
		"""
		assert issubclass (config_type, Config)

		super().__init__()

		self.__func = func
		self.__name__ = func.__name__
		self.__config_type = config_type
		self.__terminated = False
		self.__snapshot_terminated = False

		self.terminated = snapshot.Event (self, "terminated")

	def evaluate_snapshot (self):
		self.__snapshot_terminated = self.__terminated

	def match_terminated (self):
		return snapshot.EventMatch (self.terminated) if self.__snapshot_terminated else None

	def get_config_type (self):
		"""Return the type of config required by this testcase"""
		return self.__config_type

	def run (self, config):
		"""Runs the testcase.

		This function starts a new thread to run the testcase function.
		Once the testcase is terminated, it returns the final verdict.

		It also generate log events EventTestcaseStarted and
		EventTestcaseTerminated.
		"""
		assert isinstance (config, self.__config_type)

		th = snapshot.SnapshotManager.Thread (target = self.__thread_func, args = (config,))

		th.start()

		#FIXME: what happens if we are not the main thread (we'll not catch the SIGINT signals)
		self.terminated()

		return th.verdict.get_value()

	def __thread_func (self, config):
		init_verdict()

		logger.log_event (EventTestcaseStarted (self))
		try:
			with data.Data.disable_name_resolution(): # because it is very time consuming
				config.run (self, self.__func)
		except exceptions.UserInterrupt as e:
			set_verdict("aborted")
		except Exception as e:
			traceback.print_exc()
			set_verdict("error")

		logger.log_event (EventTestcaseTerminated (self, get_verdict()))

		with self.lock:
			self.__terminated = True

		gc.collect()

class EventTestcaseStarted (metaclass = logger.LogEventClass):
	fields = (("testcase", Testcase),)
	def summary (self):
		return "Testcase Started:    %s" % (self[0].__name__)

class EventTestcaseTerminated (metaclass = logger.LogEventClass):
	fields = (("testcase", Testcase),
		  ("verdict", VerdictValue),
		 )
	def summary (self):
		return "Testcase Terminated: %s --> %s" % (self[0].__name__, self[1])

class EventTestcaseRuntimeError (metaclass = logger.LogEventClass):
	fields = (("testcase", Testcase),
		  ("message", str),
		  ("traceback", str),
		 )
	def summary (self):
		return "Testcase Runtime Error: %s: %s" % (self[0].__name__, self[1])

class EventSetVerdict (metaclass = logger.LogEventClass):
	fields = (("verdict", VerdictValue),
		  ("message", str),
		 )
	def summary (self):
		return "Verdict: %s%s" % (
				self[0],
				(" - %s" % self[1]) if self[1] else "")

class TestSession (logger.LoggedObject):
	"""A class for handling test sessions

	a test session contains a list of testcases to be run and a set of
	configurations for these testcases.
	"""
	@typecheck
	def __init__ (self, testcase_list: optional (list_of (Testcase)) = None, description: str = ""):
		"""Initialise the test session

		Parameters:
		- testcase_list (opt)	list of testcases to be run (by default, all testcases are run)
		- description (opt)	description of the test session


		"""
		logger.LoggedObject.__init__(self)
		if testcase_list is None:
			self.__tc_list = list (all_testcases)
			self.__description = "all testcases"

		else:
			self.__tc_list = list (testcase_list)
			self.__description = description

		self.__configs = {Config: Config()}

	def get_description (self):
		"""Return the textual description of the test session"""
		return self.__description

	@typecheck
	def set_config (self, cfg_type: type, config: Config):
		"""Set a configuration

		This function stores which config object 'config' shall be used
		for testcases requiring the type of configuration 'cfg_type'.
		"""
		assert issubclass (cfg_type, Config)
		assert isinstance (config, cfg_type)
		self.__configs[cfg_type] = config

	def run (self):
		"""Run the test session"""

		#FIXME: not really necessary to have a separate thread
		th = snapshot.SnapshotManager.Thread (target = self.__thread_func)

		th.start()

		th.interrupt = types.MethodType (self.interrupt, th)
		th.__last_interruption = 0
		th.__interrupted = False

		#FIXME: join() w/o any timeout will not catch ^C interrupts (maybe a bug in python)
		#FIXME: what happens if we are not the main thread (we'll not catch the SIGINT signals)
		th.join(1231322222246514)

	@staticmethod
	def interrupt (thread):
		"""Function for notifying an interruption by the user.

		Once this function is called, the session thread is notified
		that it should abort the execution"""
		t = time.time()
		if (t - thread.__last_interruption) < 1:	# TODO: handle this in the user interactions interface
			thread.__interrupted = True
		thread.__last_interruption = t

	def execute (self, testcase, summary):
		"""Execute one testcase in this session

		This function selects an adequate configuration for the given
		testcase, and runs it (or report an error if the the requested
		configuration type is missing).

		The summary is updated with the outcome of the testcase.

		The function returns the final verdict of the testcase.
		"""

		cfg_type = testcase.get_config_type()

		if cfg_type in self.__configs:
			verdict = testcase.run (self.__configs[cfg_type])
		else:
			logger.log_event (EventTestSessionError (self, "missing configuration: %s" % cfg_type.__name__))
			verdict = "error"

		summary.update (testcase, verdict)

		if threading.current_thread().__interrupted:
			raise exceptions.UserInterrupt()

		return verdict

	def __thread_func (self):

		summary = VerdictSummary()

		self.log (EventTestSessionStarted)
		try:
			for tc in self.__tc_list:
				self.execute (tc, summary)

		except exceptions.UserInterrupt:
			self.log (EventTestSessionAborted)

		self.log (EventTestSessionTerminated, summary)

		gc.collect()

class EventTestSessionStarted (metaclass = logger.LogEventClass):
	fields = (("session", TestSession),)
	def summary (self):
		return "Test session started: %s" % self[0].get_description()

class EventTestSessionAborted (metaclass = logger.LogEventClass):
	fields = (("session", TestSession),)
	def summary (self):
		return "Test session aborted: %s" % self[0].get_description()

class EventTestSessionError (metaclass = logger.LogEventClass):
	fields = (("session", TestSession),
		  ("message", str))
	def summary (self):
		return "Test session error: %s" % self[1]

class EventTestSessionTerminated (metaclass = logger.LogEventClass):
	fields = (("session", TestSession),
		  ("verdict_summary", VerdictSummary))
	def summary (self):
		result = ["Test session terminated: %s\n\nTestcase results:" % self[0].get_description()]
		summary = self[1]

		for tc, v in summary.testcases():
			result.append ("\t[%s]  %s" % (str(v).center(8), tc.__name__))

		result.append("\nSummary:")
		total = summary.count()
		for v, nb in summary:
			result.append ("\t%-10s %3d  (%3d%%)" % (v, nb, nb*100//total))

		result.append ("\n\t%-10s %3d  (%3d%%)" % ("Total", total, 100))

		return "\n".join(result)

@typecheck
def testcase (arg: either (types.FunctionType, type)):
	"""Decorator function for defining testcases

	this function can be used in two ways:

	1. testcases that do not require any specific configuration. the
	testcase configuration will by default use the type config.

		@testcase
		def my_testcase():
			...

	2. testcases that requires a specific configuration. this configuration
	shall be given as parameter.

		@testcase (MyConfig)
		def my_testcase():
			...
	"""
	if isinstance (arg, type):
		assert issubclass (arg, Config)

		def tc_def (func):
			tc = Testcase (func, arg)
			all_testcases.append (tc)
			return tc
		return tc_def

	else:
		tc = Testcase (arg)
		all_testcases.append (tc)
		return tc
@typecheck
def run_all_testcases (configs: dict_of(type, Config) = {}):
	"""Run all the known testcases

	This function instantiates a TestSession with all the known testcases,
	in the order they were defined and runs it.

	The 'configs' parameter may contain a dict of the configuration objects
	to be used for each type of configuration used in the testcases.
	"""
	ts = TestSession()
	for k,v in configs.items():
		ts.set_config (k, v)
	ts.run()

def _sigint_handler (sig, frame):
	"""A handler for the SIGINT signal

	This function notifies the running threads that the user is
	interrupting the execution, so that they can terminate cleanly.
	"""
	# FIXME: it would be better to only send the interrupt signal to the main thread and let it
	#	propagate the signal to other threads (this would be more deterministic)
	for t in threading.enumerate():
		if hasattr (t, "interrupt"):
			t.interrupt()

def stop():
	raise exceptions.TerminateTestcase()

signal.signal (signal.SIGINT, _sigint_handler)

class SUTActionFailed (Exception):
	pass

# FIXME: possible race condition if one action is started when another is matched
# TODO:  support concurrent actions
class SUTAction (snapshot.EventSource, logger.LoggedObject):

	@classmethod
	def async (cls, action):
		return cls (action, async = True)

	def __new__ (cls, action, async = False):
		if async:
			return super().__new__(cls)

		# sync case
		handle = cls (action, True)

		try:
			with snapshot.alt:
				handle.done()

				@handle.error
				def _():
					set_verdict ("error", "SUT action error")
		finally:
			handle.interrupt()

	def __init__ (self, action, async):
		snapshot.EventSource.__init__ (self)
		logger.LoggedObject.__init__ (self)

		self.done  = snapshot.Event (self, "done")
		self.error = snapshot.Event (self, "error")

		with self.lock:
			self.action = action
			self.__status = None
			self.__thread = threading.Thread (target = self.__run)
			self.__thread.start()

	def __run (self):
		try:
			self.run()
			result = True
		except Exception as e:
			result = e

		with self.lock:
			self.__status = result
			self.__thread = None

	def run (self):
		raise NotImplementedError()

	def interrupt (self):
		raise NotImplementedError()

	def evaluate_snapshot (self):
		self.__snapshot_status = self.__status

	@typecheck
	def match_done (self) -> optional (snapshot.EventMatch):
		if not self.__snapshot_status:
			return None

		with self.lock:
			self.__status = None

		self.log (EventSUTActionDone, str (self.action))

		return snapshot.EventMatch (self.done)

	@typecheck
	def match_error (self) -> optional (snapshot.EventMatch):
		if not isinstance (self.__snapshot_status, Exception):
			return None

		with self.lock:
			status = self.__status
			self.__status = None

		self.log (EventSUTActionError, str (self.action), status)

		return snapshot.EventMatch (self.error)

class SUTActionManual (SUTAction):

	def __init__ (self, *k):
		self.__pid = None
		super().__init__(*k)

	def run (self):
		with self.lock:
			self.__pid = os.fork()

		if not self.__pid:
			os.execl ("/usr/bin/zenity", "zenity", "--info", "--title=TTProto", "--text=SUT informal action requested:\n\n%s" % self.action)
			print('error: execl("/usr/bin/zenity", ...) failed')
			sys.exit (1)

		pid, status = os.waitpid (self.__pid, 0)

		with self.lock:
			self.__pid = None

		if status // 256:
			raise SUTActionFailed()

	def interrupt (self):
		with self.lock:
			if self.__pid:
				os.kill (self.__pid, signal.SIGTERM)

class EventSUTActionDone (metaclass = logger.LogEventClass):
	fields = (("driver", SUTAction),
		  ("action", str),
		 )

	def summary (self):
		return "SUT action done (%s): %s" % (type(self[0]).__name__, self[1])

class EventSUTActionError (metaclass = logger.LogEventClass):
	fields = (("driver", SUTAction),
		  ("action", str),
		  ("exception", str),
		  ("traceback", str),
		 )

	def summary (self):
		return "SUT action error (%s): %s -> %s" % (type(self[0]).__name__, self[1], repr(self[2]))

#@testcase
#def hello_world():
#	"""Sample hello world test case"""
#	print ("Hello World!")
#	set_verdict ("pass")

