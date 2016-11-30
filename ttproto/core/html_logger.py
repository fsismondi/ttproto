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

import os, sys, threading, time, traceback, types

from ttproto.core.typecheck import *
from ttproto.core import xmlgen, control, logger, port, data
from ttproto.core.list import ListValue
from ttproto.core.packet import PacketValue


__all__ = [
    "HTMLLogger",
]

# TODO: should be configurable
ROOT_DIR = "reports"


def _gen_dir(root_dir):
    assert os.path.exists(root_dir)

    base = time.strftime("%Y-%m-%d--%Hh%M")
    d = base
    n = 1
    while os.path.exists(os.path.join(root_dir, d)):
        n += 1
        d = "%s-%d" % (base, n)

    return d



class HTMLLogger(logger.Logger):
    __verdict_color_map = {
        None: "#FF9090",
        "none": "#FFFFA0",
        "pass": "#B0FFB0",
        "inconclusive": "#DCBAFF",
    }

    class __RuntimeError(Exception):
        def __init__(self, exc_type, exc_value, traceback):
            Exception.__init__(self)
            self.__info = exc_type, exc_value, traceback

        def exc_info(self):
            return self.__info

    class __Exit(Exception):
        pass

    def __init__(self, directory=None):
        self.__lock = threading.Lock()
        self.__usage_count = 0
        self.__requested_dir = directory
        self.__event = None

    def __enter__(self):
        with self.__lock:
            if self.__usage_count == 0:
                if not os.path.exists(ROOT_DIR):
                    os.mkdir(ROOT_DIR)

                session_dir = self.__requested_dir if self.__requested_dir else _gen_dir(ROOT_DIR)
                self.__dir = os.path.join(ROOT_DIR, session_dir)
                os.mkdir(self.__dir)  # the output directory must not exist

                if not self.__requested_dir:
                    # create a symlink current
                    current = os.path.join(ROOT_DIR, "current")
                    if os.path.exists(current):
                        if os.path.islink(current):
                            os.unlink(current)
                            os.symlink(session_dir, current)
                        else:
                            print("Warning: cannot create symlink 'current'")
                    else:
                        os.symlink(session_dir, current)

                self.__tc_count = 0

                self.__generators = self.gen_index(), self.gen_tc_report(), self.gen_tc_messages(), self.gen_tc_mismatch()
                self.__iteration()

            self.__usage_count += 1

        return self

    def __exit__(self, a, b, c):
        with self.__lock:
            if a:
                err = self.__RuntimeError(a, b, c)
                for g in self.__generators:
                    try:
                        g.throw(err)
                    except self.__RuntimeError as e:
                        print("HTML generator %s did no handle exception %s" % (str(g), str(e)))

            self.__usage_count -= 1
            if self.__usage_count == 0:
                for g in self.__generators:
                    g.close()

    def __iteration(self):
        assert self.__lock.locked()

        for g in self.__generators:
            # TODO: catch possible exceptions ?
            try:
                next(g)
            except StopIteration:
                pass

        if type(self.__event) == control.EventTestcaseTerminated:
            self.__tc_count += 1

    @classmethod
    def __verdict_col(cls, v):
        vcm = cls.__verdict_color_map
        return vcm[v] if v in vcm else vcm[None]

    @typecheck
    def log_event(self, event: logger.LogEvent):
        with self.__lock:
            if self.__usage_count:
                self.__event = event
                self.__iteration()

                # clear the event so as not to interfere with the garbage collector
                self.__event = None
            else:
                print("Warning: ignored event:", event, file=sys.stderr)

    def gen_index(self):
        with xmlgen.XHTML10Generator(output=os.path.join(self.__dir, "index.html"), indented=True) as g:
            gctrl = xmlgen.XMLGeneratorControl(g)

            while type(self.__event) != control.EventTestSessionStarted:
                yield

            title = "Test Session Report - " + self.__event.session.get_description()

            g.head.title(title)
            g.h1(title)

            try:
                with g.table(border=1, cellspacing=0, cellpadding=5):
                    with g.tr:
                        g.th("Testcase")
                        g.th("Report")
                        g.th("Messages")
                        g.th("Verdict")

                        while True:
                            while type(self.__event) != control.EventTestcaseStarted:
                                yield
                                if type(self.__event) == control.EventTestSessionTerminated:
                                    raise self.__Exit()

                            with g.tr:
                                g.td(self.__event.testcase.__name__)
                                g.td(align="center").a(href="tc-%03d-report.html" % self.__tc_count)("X")
                                g.td(align="center").a(href="tc-%03d-messages.html" % self.__tc_count)("X")
                                gctrl.flush()

                                while type(self.__event) != control.EventTestcaseTerminated:
                                    yield

                                v = self.__event.verdict
                                g.td(bgcolor=self.__verdict_col(v))(v)

            except GeneratorExit:
                g.b("Warning: the HTML logging module shut down before the end of the test session")

            except self.__RuntimeError as e:
                g.b("Error in the logging module")
                g.pre("".join(traceback.format_exception(*e.exc_info())))

            except self.__Exit:
                g.h1("Summary")
                with g.table(border=1, cellspacing=0, cellpadding=5):
                    total = self.__event.verdict_summary.count()
                    for name, nb in self.__event.verdict_summary:
                        tr = g.tr
                        if nb:
                            tr(bgcolor=self.__verdict_col(name))
                        with tr:
                            g.td(name)
                            g.td(" %d" % nb, align="right")
                            g.td(" %3d%%" % (nb * 100 // total), align="right")

            except Exception:
                print("(blah)")
                g.b("Error in the logging module")
                g.pre("".join(traceback.format_exception(*sys.exc_info())))

        # TODO: return an error status to the logger object
        while True:
            yield

    def gen_tc_report(self):
        while True:

            while type(self.__event) != control.EventTestcaseStarted:
                yield

            with xmlgen.XHTML10Generator(output=os.path.join(self.__dir, "tc-%03d-report.html" % self.__tc_count),
                                         indented=False) as g:
                gctrl = xmlgen.XMLGeneratorControl(g)

                title = "Test Case Report - " + self.__event.testcase.__name__

                g.head.title(title)
                g.h1(title)

                try:
                    with g.table(border=1, cellspacing=0, celpadding=5):
                        with g.tr:
                            g.th("Timestamp")
                            g.th("Info")
                            g.th("Message")
                        while True:
                            e = self.__event

                            with g.tr:
                                g.td(e.get_timestamp())

                                if type(e) in (port.EventMessageSent, port.EventMessageReceived):
                                    if type(e) == port.EventMessageSent:
                                        g.td("Message sent to " + e.port.__name__)
                                    else:
                                        g.td("Message received from " + e.port.__name__)
                                    g.td.a(href="tc-%03d-messages.html#%x" % (self.__tc_count, id(e.message))).tt(
                                        style="white-space: pre")(e.message.get_description())

                                else:
                                    if type(e) == port.EventMessageMismatch:
                                        g.td.a(href="tc-%03d-mismatch.html#%x" % (self.__tc_count, id(e)))(e.summary())
                                    elif type(e) == control.EventTestcaseRuntimeError:
                                        with g.td:
                                            g(e.summary())
                                            g.pre(e.traceback)
                                    elif type(e) == control.EventSetVerdict:
                                        g.td(e.summary(), bgcolor=self.__verdict_col(e.verdict))
                                    elif type(e) == logger.EventStep:
                                        g.td(e.summary(), bgcolor="#e8e8e8")
                                    else:
                                        g.td(e.summary())

                                    g.td(
                                        "")  # g.td  FIXME: xmlgen <td/> not flushed in the right placf without function call

                                if type(e) == control.EventTestcaseTerminated:
                                    raise self.__Exit()

                            yield

                except self.__Exit:
                    pass

        # TODO: return an error status to the logger object
        while True:
            yield

    def gen_tc_messages(self):
        while True:

            while type(self.__event) != control.EventTestcaseStarted:
                yield

            with xmlgen.XHTML10Generator(output=os.path.join(self.__dir, "tc-%03d-messages.html" % self.__tc_count),
                                         indented=True) as g:
                gctrl = xmlgen.XMLGeneratorControl(g)

                title = "Test Case Messages Report - " + self.__event.testcase.__name__

                g.head.title(title)
                g.h1(title)

                nb = 0
                try:
                    while True:
                        e = None
                        while type(e) not in (port.EventMessageSent, port.EventMessageReceived):
                            yield
                            e = self.__event
                            if type(e) == control.EventTestcaseTerminated:
                                raise self.__Exit()

                        nb += 1

                        g.a(name="%x" % id(e.message))
                        g.hr
                        g.p.b("Message #%d %s on %s at %s (%f)" % (
                            nb, "sent" if type(e) == port.EventMessageSent else "received",
                            e.port.__name__,
                            time.ctime(e.get_timestamp()), e.get_timestamp()))
                        with g.p:
                            m = e.message
                            g.pre(str(m.get_description()) + "\n\n")

                            self.display_value(g, m.get_value())

                            with g.pre:
                                g("\n\n")
                                b = m.get_binary()
                                for offset in range(0, len(b), 16):
                                    values = ["%02x" % v for v in b[offset:offset + 16]]
                                    if len(values) > 8:
                                        values.insert(8, " ")

                                    g("%04x   %s" % (offset, " ".join(values)))


                except self.__Exit:
                    pass

        # TODO: return an error status to the logger object
        while True:
            yield

    class __ExtraColumnMatchResult:
        def __init__(self, value, pattern, mismatches: tuple_of(data.Mismatch)):
            self.__iter_diff = iter(mismatches)
            self.__next_diff()

            self.__iter_value_pattern = self.__value_pattern_generator(value, pattern)
            self.__next_value_pattern()

        def __next_value_pattern(self):
            try:
                result = next(self.__iter_value_pattern)
                self.__value, self.__pattern = result
            except StopIteration:
                self.__value, self.__pattern = None, None

            return self.__value, self.__pattern

        def __value_pattern_generator(self, value, pattern):

            yield value, pattern

            # do not go further if pattern is a template, or if its type is different
            if (not isinstance(pattern, data.Value)) or value.get_type() != pattern.get_type():
                return

            # from here we have the same type
            if isinstance(value, PacketValue):
                if value.get_variant() != pattern.get_variant():
                    # variant mismatch -> we only report the first fields
                    for f1, f2, v, p in zip(value.get_variant().fields(), pattern.get_variant().fields(), value,
                                            pattern):
                        if f1 != f2:
                            break

                        for v_p in self.__value_pattern_generator(v, p):
                            yield v_p
                else:
                    for v, p in zip(value, pattern):
                        for v_p in self.__value_pattern_generator(v, p):
                            yield v_p

            elif isinstance(value, ListValue) and value.get_type().is_ordered():
                # TODO: not ordered case
                for v, p in zip(value, pattern):
                    for v_p in self.__value_pattern_generator(v, p):
                        yield v_p

        def __next_diff(self):
            try:
                # NOTE: may have several times the same value, but different patterns (inherited templates)
                self.__diff = next(self.__iter_diff)
            # print ("next diff:", self.__diff.value, self.__diff.pattern)
            except StopIteration:
                self.__diff = None
            # print ("next diff: none")

            return self.__diff

        def __call__(self, g, value):
            d = self.__diff

            if value is not self.__value:
                pattern = None
            else:
                pattern = self.__pattern
                self.__next_value_pattern()

            # print ("iteration:", value, pattern)

            with g.td(
                    bgcolor="#FF9090" if d and d.value is value else "white"):  # FIXME: will not work in case we have strange matches (especially with one template containing values or with an unordered set). the mismatchlist should be a tree

                # ensure that pattern 'contains' d.pattern (possibly multiples d.pattern instances)
                if d and d.value is value:
                    while True:
                        if not d or not d.value is value:
                            break
                        g("%s: expected %s" % (type(d).__name__, d.describe_expected()))
                        g.br

                        d = self.__next_diff()

                elif pattern:
                    if not isinstance(pattern, data.Value):
                        expected = str(pattern)
                    elif pattern.get_type() != value.get_type():
                        if isinstance(pattern, PacketValue):
                            expected = pattern.get_variant().__name__
                        else:
                            expected = pattern.get_type().__name__
                    elif isinstance(value, PacketValue) and pattern.get_variant() != value.get_variant():
                        expected = pattern.get_variant().__name__
                    else:
                        if isinstance(pattern, PacketValue) or isinstance(pattern, ListValue):
                            # just display the type
                            if isinstance(pattern, PacketValue):
                                expected = pattern.get_variant().__name__
                            else:
                                expected = pattern.get_type().__name__
                        else:
                            expected = str(pattern)

                    g("expected %s" % expected)

    def gen_tc_mismatch(self):
        while True:

            while type(self.__event) != control.EventTestcaseStarted:
                yield

            with xmlgen.XHTML10Generator(output=os.path.join(self.__dir, "tc-%03d-mismatch.html" % self.__tc_count),
                                         indented=True) as g:
                gctrl = xmlgen.XMLGeneratorControl(g)

                title = "Mismatch Reports - " + self.__event.testcase.__name__

                g.head.title(title)
                g.h1(title)

                nb = 0
                try:
                    while True:
                        e = None
                        while type(e) != port.EventMessageMismatch:
                            yield
                            e = self.__event
                            if type(e) == control.EventTestcaseTerminated:
                                raise self.__Exit()

                        nb += 1

                        g.a(name="%x" % id(e))
                        g.hr
                        g.p.b("Message mismatch #%d on %s at %s (%f)" % (
                            nb, e.port.__name__,
                            time.ctime(e.get_timestamp()), e.get_timestamp()))
                        with g.p.pre:
                            g(e.message.get_description())
                            g("\n")

                        self.display_value(g, e.message.get_value(),
                                           self.__ExtraColumnMatchResult(e.message.get_value(), e.pattern,
                                                                         e.mismatches))

                except self.__Exit:
                    pass

        # TODO: return an error status to the logger object
        while True:
            yield

    @typecheck
    def calc_output_size(self, value: data.Value):
        if isinstance(value, PacketValue):
            c_lines = 0
            c_cols = 1
            pid = value.get_variant().get_payload_id()
            for i in range(0, len(value)):
                l, c = self.calc_output_size(value[i])
                if i == pid:
                    c -= 1
                c_lines += l
                if c > c_cols:
                    c_cols = c
            result = (1 + c_lines), (2 + c_cols)

        elif isinstance(value, ListValue):
            c_lines = 0
            c_cols = 1
            for i in range(0, len(value)):
                l, c = self.calc_output_size(value[i])
                c_lines += l
                if c > c_cols:
                    c_cols = c
            result = (1 + c_lines), (1 + c_cols)

        else:
            result = (1, 1)

        value.__output_size = result
        return result

    @typecheck
    def display_value(self, g: xmlgen.XMLGenerator, value: data.Value, col_add: optional(callable) = None):
        l, c = self.calc_output_size(value)
        with g.table(border=1, cellspacing=0, cellpadding=2, width=("800px" if col_add else "640px")):
            self.__display_value_internal(g, value, col_add)



    def __display_value_internal(self, g: xmlgen.XMLGenerator, value: data.Value, col_add: optional(callable),
                                 prefix=None, data_span=1, description=None):

        l, c = value.__output_size
        col_style = "border-left-width: medium; border-top-width: medium; border-right: none"
        headline_style = "border-top-width: medium; border-left: none; padding-top: 4pt; padding-bottom: 5pt"
        prefix_style = "padding-left: 10pt; border-left: none"
        if l != 1:
            rowspan = {"rowspan": l}
        else:
            rowspan = {}

        if isinstance(value, PacketValue):
            with g.tr:
                if prefix:
                    g.td(style=prefix_style, **rowspan)(prefix)
                g.td(style=col_style, **rowspan)(" ")
                g.th(colspan=c - 1, align="left", style=headline_style)(value.get_variant().__name__)
                if col_add:
                    col_add(g, value)
            i = 0
            for f in value.get_variant().fields():
                self.__display_value_internal(g, value[i], col_add, f.name if f.name != "Payload" else None, c - 2,
                                              value.get_description(i))
                i += 1

        elif isinstance(value, ListValue):
            with g.tr:
                if prefix:
                    g.td(style=prefix_style, **rowspan)(prefix)
                g.td(rowspan=l, style=col_style)(" ")
                g.th(colspan=c - 1, align="left", style=headline_style)(value.get_type().__name__)

                if col_add:
                    col_add(g, value)

            for i in range(0, len(value)):
                self.__display_value_internal(g, value[i], col_add, None, c - 1)


        else:
            with g.tr:
                if prefix:
                    if data_span != 1:
                        g.td(colspan=data_span, style=prefix_style)(prefix)
                        data_span = 1
                    else:
                        g.td(style=prefix_style)(prefix)
                else:
                    data_span += 1

                txt = str(value)

                if description is not None:
                    txt = "%s (%s)" % (txt, description)

                if data_span != 1:
                    g.td(colspan=data_span)(txt)
                else:
                    g.td(txt)

                if col_add:
                    col_add(g, value)

