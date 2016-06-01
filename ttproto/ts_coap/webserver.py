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

import http.server, io, sys, email.feedparser, email.message, os, errno, tempfile, re, time, signal, select, subprocess
from . import analysis
from ttproto.utils import pure_pcapy
from ttproto.core.xmlgen import XHTML10Generator, XMLGeneratorControl


DATADIR = "data"
TMPDIR = "tmp"
LOGDIR = "log"

CHANGELOG = []

CHANGELOG_FIRST_COMMIT = "iot2-beta"

def prepare_changelog():
	global CHANGELOG
	CHANGELOG = []

	try:
		lines = None

		# NOTE: limite log to first parent to avoid the burden of having verbose changelog about tool updates
		#	-> put tool updates in branch 'tool'
		#	-> put test suites updates in branch 'master'
		#	-> merge 'tool' into 'master' using « --no-ff --no-commit » and put summary changes about the tool
		git_cmd = ['git', 'log', '--format=format:%cD\n%h\n%d\n%B\n_____end_commit_____', '--first-parent']

		if CHANGELOG_FIRST_COMMIT:
			git_cmd.append ("%s^1.." % CHANGELOG_FIRST_COMMIT)

		git_log = iter (str (subprocess.Popen (
				git_cmd,
				stdout = subprocess.PIPE,
				close_fds = True,
			).stdout.read(), "utf8", "replace").splitlines())

		while True:
			date = next (git_log)
			ver  = next (git_log)
			tags = next (git_log)
			if tags:
				tags = tags[2:-1]
			lines = []
			while True:
				l = next (git_log)
				if l == "_____end_commit_____":
					break
				lines.append (l)

			if lines and lines[-1] != "":
				lines.append("") # ensure that there will be a \n at the end
			CHANGELOG.append ((ver, tags, date, "\n".join(lines)))
	except StopIteration:
		pass
	except Exception as e:
		CHANGELOG = [(("error when generating changelog (%s: %s)" % (type (e).__name__, e)), "", "", "")]


#prepare_changelog()

def html_changelog (g):

	ctl = XMLGeneratorControl(g)

	g.h2 ("Changelog")
	for ver, tags, date, body in CHANGELOG:
		if tags:
			g.b("%s" % (tags))
			ctl.raw_write ("<br>") # FIXME: bug in xmlgen
		g.span("%s - %s\n\n" % (ver, date), style="color:#808080")

		g.pre("\t%s\n\n" % "\n\t".join (body.splitlines()))



class UTF8Wrapper (io.TextIOBase):
	def __init__ (self, raw_stream):
		self.__raw = raw_stream

	def write (self, string):

		return self.__raw.write (bytes (string, "utf-8"))

class BytesFeedParser (email.feedparser.FeedParser):
    """Like FeedParser, but feed accepts bytes."""

    def feed(self, data):
        super().feed(data.decode('ascii', 'surrogateescape'))

class RequestHandler (http.server.BaseHTTPRequestHandler):

	def log_message(self, format, *args, append = ""):
		global log_file
		host = self.address_string()
		if host in ("172.17.42.1", "localhost", "127.0.0.1", "::1"):
			xff = self.headers.get("x-forwarded-for")
			if xff:
				host = xff

		txt = ("%s - - [%s] %s - %s\n%s" %
				 (host,
				  self.log_date_time_string(),
				  format % args,
				  self.headers.get("user-agent"),
				  "".join ("\t%s\n" % l for l in append.splitlines()),
			))

		sys.stderr.write (txt)
		log_file.write(txt)
		log_file.flush()

	def do_GET (self):

		if self.path == "/coap-tool.sh":
			fp = open ("coap-tool.sh", "rb")

			if not fp:
				self.send_response (500)
				return

			self.send_response (200)
			self.send_header ("Content-Type", "text/x-sh")
			self.end_headers()

			self.wfile.write (fp.read())
			return
		if self.path == "/doc/ETSI-CoAP4-test-list.pdf":
			fp = open ("doc/ETSI-CoAP4-test-list.pdf", "rb")

			if not fp:
				self.send_response (500)
				return

			self.send_response (200)
			self.send_header ("Content-Type", "application/pdf")
			self.end_headers()

			self.wfile.write (fp.read())
			return
		if self.path == "/doc/Additive-IRISA-CoAP-test-list.pdf":
			fp = open ("doc/Additive-IRISA-CoAP-test-list.pdf", "rb")

			if not fp:
				self.send_response (500)
				return

			self.send_response (200)
			self.send_header ("Content-Type", "application/pdf")
			self.end_headers()

			self.wfile.write (fp.read())
			return
		if self.path == "/doc/Additive-IRISA-CoAP-test-description.pdf":
			fp = open ("doc/Additive-IRISA-CoAP-test-description.pdf", "rb")

			if not fp:
				self.send_response (500)
				return

			self.send_response (200)
			self.send_header ("Content-Type", "application/pdf")
			self.end_headers()

			self.wfile.write (fp.read())
			return
		if self.path != "/":
			self.send_error (404)
			return

		self.send_response (200)
		self.send_header ("Content-Type", "text/html;charset=utf-8")
		self.end_headers()

		with XHTML10Generator (output = UTF8Wrapper (self.wfile)) as g:

			with g.head:
				g.title ("IRISA CoAP interoperability Testing Tool")
				g.style ("img {border-style: solid; border-width: 20px; border-color: white;}", type = "text/css")

			g.h1 ("IRISA CoAP interoperability Testing Tool")

			g.b("Tool version: ")
			g("%s" % analysis.TOOL_VERSION)
			with g.br(): # FIXME: bug generator
				pass
			with g.form (method="POST", action="submit", enctype="multipart/form-data"):
				g("This tool (more details at ")
				g.a("www.irisa.fr/tipi", href="http://www.irisa.fr/tipi/wiki/doku.php/passive_validation_tool_for_coap")
				g(") allows executing CoAP interoperability test suites (see below Available Test Scenarios) on the provided traces of CoAP Client-Server interactions.")
				g.br()
				g.h3("Available Test Scenarios:")
				g("- ETSI COAP#4 Plugtest scenarios: ")
				g.a("ETSI-CoAP4-test-list", href="doc/ETSI-CoAP4-test-list.pdf")
				g(", ")
				g.a("ETSI-CoAP4-test-description", href="https://github.com/cabo/td-coap4/")
				with g.br(): # FIXME: bug in generation if we remove the with context
					pass
				g("- Additive test scenarios developed by IRISA/Tipi Group: ")
				g.a("Additive-IRISA-CoAP-test-list", href="doc/Additive-IRISA-CoAP-test-list.pdf")
				g(", ")
				g.a("Additive-IRISA-CoAP-test-description", href="doc/Additive-IRISA-CoAP-test-description.pdf")
				with g.br(): # FIXME: bug in generation if we remove the with context
					pass
				g.h3("IETF RFCs/Drafts covered:")
				g("- CoAP CORE (")
				g.a("RFC7252",href="http://tools.ietf.org/html/rfc7252")
				g(")")
				with g.br(): # FIXME: bug in generation if we remove the with context
					pass
				g("- CoAP OBSERVE (")
				g.a("draft-ietf-core-observe-16",href="http://tools.ietf.org/html/draft-ietf-core-observe-16")
				g(")")
				with g.br(): # FIXME: bug in generation if we remove the with context
					pass
				g("- CoAP BLOCK (")
				g.a("draft-ietf-core-block-17",href="http://tools.ietf.org/html/draft-ietf-core-block-17")
				g(")")
				g.br()
				with g.br(): # FIXME: bug in generation if we remove the with context
					pass


				g("==========================================================================================")
				with g.br(): # FIXME: bug in generation if we remove the with context
					pass
				g("Submit your traces (pcap format). \nWarning!! pcapng format is not supported; you should convert your pcapng file to pcap format.")
				with g.br(): # FIXME: bug in generation if we remove the with context
					pass
				g.input (name="file", type="file", size=60)
				with g.br(): # FIXME: bug in generation if we remove the with context
					pass
				g("Configuration")
				g.br()
				with g.select (name="profile"):
					g.option ("Client <-> Server", value="client", selected="1")
					g.option ("Reverse-Proxy <-> Server", value="reverse-proxy")
				with g.br(): # FIXME: bug in generation if we remove the with context
					pass
				g("Optional regular expression for selecting scenarios (eg: ")
				g.tt("CORE_0[1-2]")
				g(" will run only ")
				g.tt("TD_COAP_CORE_01")
				g(" and ")
				g.tt("TD_COAP_CORE_02")
				g(")")
				g.br()
				g.input (name="regex", size=60)
				g.br()
				with g.br(): # FIXME: bug in generation if we remove the with context
					pass
				with g.input (name="agree", type="checkbox", value="1"):
					pass
				g("I agree to leave a copy of this file on the server (for debugging purpose). Thanks")

				g.br()

				with g.input (name="urifilter", type="checkbox", value="1"):
					pass
				g("Filter conversations by URI (/test vs. /separate vs. /.well-known/core  ...) to reduce verbosity")

				g.br()
				g.br()
				g.input (type="submit")
				with g.br(): # FIXME: bug generator
					pass
				g.b("Note:")
				g(" alternatively you can use the shell script ")
				g.a("coap-tool.sh", href="coap-tool.sh")
				g(" to capture and submit your traces to the server (requires tcpdump and curl installed on your system).")

			g.a(href="http://www.irisa.fr/tipi").img (src="http://www.irisa.fr/tipi/wiki/lib/tpl/tipi_style/images/irisa.jpg", height="40")

			g.a(href="http://www.irisa.fr/tipi").img (src="http://www.irisa.fr/tipi/wiki/lib/tpl/tipi_style/images/tipi_small.png", height="50")

			html_changelog (g)

	def do_POST (self):
		if (self.path != "/submit"):
			self.send_error (404)
			return

		global job_id
		job_id += 1

		if os.fork():
			# close the socket right now (because the
			# requesthandler may do a shutdown(), which triggers a
			# SIGCHLD in the child process)
			self.connection.close()
			return

		parser = BytesFeedParser()
		ct = self.headers.get ("Content-Type")
		if not ct.startswith("multipart/form-data;"):
			self.send_error (400)
			return

		parser.feed (bytes ("Content-Type: %s\r\n\r\n" % ct, "ascii"))
		parser.feed (self.rfile.read (int (self.headers['Content-Length'])))
		msg = parser.close()


		# agree checkbox is selected
		for part in msg.get_payload():
			if isinstance (part, email.message.Message):
				disposition = part.get ("content-disposition")
				if disposition and 'name="agree"' in disposition:
					agree = True
					break
		else:
			agree = False

		# urifilter checkbox is selected
		for part in msg.get_payload():
			if isinstance (part, email.message.Message):
				disposition = part.get ("content-disposition")
				if disposition and 'name="urifilter"' in disposition:
					urifilter = True
					break
		else:
			urifilter = False

		# content of the regex box
		for part in msg.get_payload():
			if isinstance (part, email.message.Message):
				disposition = part.get ("content-disposition")
				if disposition and 'name="regex"' in disposition:
					regex = part.get_payload()
					if not regex:
						regex = None
					break
		else:
			regex = None

		# profile radio buttons
		for part in msg.get_payload():
			if isinstance (part, email.message.Message):
				disposition = part.get ("content-disposition")
				if disposition and 'name="profile"' in disposition:
					profile = part.get_payload()
					break
		else:
			profile = "client"

		# receive the pcap file
		for part in msg.get_payload():
			if isinstance (part, email.message.Message):
				disposition = part.get ("content-disposition")
				if disposition and 'name="file"' in disposition:
					mo = re.search ('filename="([^"]*)"', disposition)

					orig_filename = mo.group(1) if mo else None

					timestamp = time.strftime("%y%m%d_%H%M%S")

					pcap_file = os.path.join (
							(DATADIR if agree else TMPDIR),
							"%s_%04d.dump" % (timestamp, job_id)
					)
					self.log_message ("uploading %s (urifilter=%r, regex=%r)", pcap_file, urifilter, regex)
					with open (pcap_file, "wb") as fd:
						# FIXME: using hidden API (._payload) because it seems that there is something broken with the encoding when getting the payload using .get_payload()
						fd.write (part._payload.encode("ascii", errors="surrogateescape"))

					break
		else:
			self.send_error (400)
			return


		self.send_response (200)
		self.send_header ("Content-Type", "text/html;charset=utf-8")
		self.end_headers()

		out=UTF8Wrapper(self.wfile)

		self.wfile.flush()

		os.dup2 (self.wfile.fileno(), sys.stdout.fileno())

		try:
			exceptions = []
			analysis.analyse_file_html (pcap_file, orig_filename, urifilter, exceptions, regex, profile)
			for tc in exceptions:
				self.log_message ("exception in %s", type(tc).__name__, append = tc.exception)
		except pure_pcapy.PcapError:
			print ("Bad file format!")

		shutdown()

job_id = 0


__shutdown = False
def shutdown():
	global __shutdown
	__shutdown = True

for d in TMPDIR, DATADIR, LOGDIR:
	try:
		os.makedirs (d)
	except OSError as e:
		if e.errno != errno.EEXIST:
			raise

def reopen_log_file (signum, frame):
	global log_file
	log_file = open (os.path.join (LOGDIR, "webserver.log"), "a")

# reopen_log_file (None, None)
#
# # log rotation
# # -> reopen the log file upon SIGHUP
# signal.signal (signal.SIGHUP, reopen_log_file)
#
# server=http.server.HTTPServer (("0.0.0.0", 2080), RequestHandler)
# while not __shutdown:
# 	try:
# 		l = log_file
# 		server.handle_request()
# 	except select.error:
# 		# do not abort when we receive a signal
# 		if l == log_file:
# 			raise
#
# 	if len(sys.argv) > 1:
# 		break

