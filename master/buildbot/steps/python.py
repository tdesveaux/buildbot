# This file is part of Buildbot.  Buildbot is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright Buildbot Team Members

from __future__ import annotations

import re
from pathlib import PurePath
from typing import Iterable

from twisted.internet import defer

from buildbot import config
from buildbot.process import buildstep
from buildbot.process import logobserver
from buildbot.process import remotecommand
from buildbot.process.results import FAILURE
from buildbot.process.results import SUCCESS
from buildbot.process.results import WARNINGS
from buildbot.process.results import statusToString
from buildbot.steps.worker import RemoveDirectory


class BuildEPYDoc(buildstep.ShellMixin, buildstep.BuildStep):
    name = "epydoc"
    command = ["make", "epydocs"]
    description = "building epydocs"
    descriptionDone = "epydoc"

    def __init__(self, **kwargs):
        kwargs = self.setupShellMixin(kwargs)
        super().__init__(**kwargs)
        self.addLogObserver('stdio', logobserver.LineConsumerLogObserver(self._log_consumer))

    def _log_consumer(self):
        self.import_errors = 0
        self.warnings = 0
        self.errors = 0

        while True:
            _, line = yield
            if line.startswith("Error importing "):
                self.import_errors += 1
            if line.find("Warning: ") != -1:
                self.warnings += 1
            if line.find("Error: ") != -1:
                self.errors += 1

    def getResultSummary(self):
        summary = ' '.join(self.descriptionDone)
        if self.import_errors:
            summary += f" ierr={self.import_errors}"
        if self.warnings:
            summary += f" warn={self.warnings}"
        if self.errors:
            summary += f" err={self.errors}"
        if self.results != SUCCESS:
            summary += f' ({statusToString(self.results)})'
        return {'step': summary}

    @defer.inlineCallbacks
    def run(self):
        cmd = yield self.makeRemoteShellCommand()
        yield self.runCommand(cmd)

        stdio_log = yield self.getLog('stdio')
        yield stdio_log.finish()

        if cmd.didFail():
            return FAILURE
        if self.warnings or self.errors:
            return WARNINGS
        return SUCCESS


class PyFlakes(buildstep.ShellMixin, buildstep.BuildStep):
    name = "pyflakes"
    command = ["make", "pyflakes"]
    description = "running pyflakes"
    descriptionDone = "pyflakes"
    flunkOnFailure = False

    # any pyflakes lines like this cause FAILURE
    _flunkingIssues = ("undefined",)

    _MESSAGES = ("unused", "undefined", "redefs", "import*", "misc")

    def __init__(self, *args, **kwargs):
        # PyFlakes return 1 for both warnings and errors. We
        # categorize this initially as WARNINGS so that
        # evaluateCommand below can inspect the results more closely.
        kwargs['decodeRC'] = {0: SUCCESS, 1: WARNINGS}

        kwargs = self.setupShellMixin(kwargs)
        super().__init__(*args, **kwargs)

        self.addLogObserver('stdio', logobserver.LineConsumerLogObserver(self._log_consumer))

        counts = self.counts = {}
        summaries = self.summaries = {}
        for m in self._MESSAGES:
            counts[m] = 0
            summaries[m] = []

        # we need a separate variable for syntax errors
        self._hasSyntaxError = False

    def _log_consumer(self):
        counts = self.counts
        summaries = self.summaries
        first = True
        while True:
            stream, line = yield
            if stream == 'h':
                continue
            # the first few lines might contain echoed commands from a 'make
            # pyflakes' step, so don't count these as warnings. Stop ignoring
            # the initial lines as soon as we see one with a colon.
            if first:
                if ':' in line:
                    # there's the colon, this is the first real line
                    first = False
                    # fall through and parse the line
                else:
                    # skip this line, keep skipping non-colon lines
                    continue

            if line.find("imported but unused") != -1:
                m = "unused"
            elif line.find("*' used; unable to detect undefined names") != -1:
                m = "import*"
            elif line.find("undefined name") != -1:
                m = "undefined"
            elif line.find("redefinition of unused") != -1:
                m = "redefs"
            elif line.find("invalid syntax") != -1:
                self._hasSyntaxError = True
                # we can do this, because if a syntax error occurs
                # the output will only contain the info about it, nothing else
                m = "misc"
            else:
                m = "misc"

            summaries[m].append(line)
            counts[m] += 1

    def getResultSummary(self):
        summary = ' '.join(self.descriptionDone)
        for m in self._MESSAGES:
            if self.counts[m]:
                summary += f" {m}={self.counts[m]}"

        if self.results != SUCCESS:
            summary += f' ({statusToString(self.results)})'

        return {'step': summary}

    @defer.inlineCallbacks
    def run(self):
        cmd = yield self.makeRemoteShellCommand()
        yield self.runCommand(cmd)

        stdio_log = yield self.getLog('stdio')
        yield stdio_log.finish()

        # we log 'misc' as syntax-error
        if self._hasSyntaxError:
            yield self.addCompleteLog("syntax-error", "\n".join(self.summaries['misc']))
        else:
            for m in self._MESSAGES:
                if self.counts[m]:
                    yield self.addCompleteLog(m, "\n".join(self.summaries[m]))
                self.setProperty(f"pyflakes-{m}", self.counts[m], "pyflakes")
            self.setProperty("pyflakes-total", sum(self.counts.values()), "pyflakes")

        if cmd.didFail() or self._hasSyntaxError:
            return FAILURE
        for m in self._flunkingIssues:
            if m in self.counts and self.counts[m] > 0:
                return FAILURE
        if sum(self.counts.values()) > 0:
            return WARNINGS
        return SUCCESS


class PyLint(buildstep.ShellMixin, buildstep.BuildStep):
    """A command that knows about pylint output.
    It is a good idea to add --output-format=parseable to your
    command, since it includes the filename in the message.
    """

    name = "pylint"
    description = "running pylint"
    descriptionDone = "pylint"

    # pylint's return codes (see pylint(1) for details)
    # 1 - 16 will be bit-ORed

    RC_OK = 0
    RC_FATAL = 1
    RC_ERROR = 2
    RC_WARNING = 4
    RC_REFACTOR = 8
    RC_CONVENTION = 16
    RC_USAGE = 32

    # Using the default text output, the message format is :
    # MESSAGE_TYPE: LINE_NUM:[OBJECT:] MESSAGE
    # with --output-format=parseable it is: (the outer brackets are literal)
    # FILE_NAME:LINE_NUM: [MESSAGE_TYPE[, OBJECT]] MESSAGE
    # message type consists of the type char and 4 digits
    # The message types:

    _MESSAGES = {
        'C': "convention",  # for programming standard violation
        'R': "refactor",  # for bad code smell
        'W': "warning",  # for python specific problems
        'E': "error",  # for much probably bugs in the code
        'F': "fatal",  # error prevented pylint from further processing.
        'I': "info",
    }

    _flunkingIssues = ("F", "E")  # msg categories that cause FAILURE

    _msgtypes_re_str = f"(?P<errtype>[{''.join(list(_MESSAGES))}])"
    _default_line_re = re.compile(rf'^{_msgtypes_re_str}(\d+)?: *\d+(, *\d+)?:.+')
    _default_2_0_0_line_re = re.compile(
        rf'^(?P<path>[^:]+):(?P<line>\d+):\d+: *{_msgtypes_re_str}(\d+)?:.+'
    )
    _parseable_line_re = re.compile(
        rf'(?P<path>[^:]+):(?P<line>\d+): \[{_msgtypes_re_str}(\d+)?(\([a-z-]+\))?[,\]] .+'
    )

    def __init__(self, store_results=True, **kwargs):
        kwargs = self.setupShellMixin(kwargs)
        super().__init__(**kwargs)
        self._store_results = store_results
        self.counts = {}
        self.summaries = {}

        for m in self._MESSAGES:
            self.counts[m] = 0
            self.summaries[m] = []

        self.addLogObserver('stdio', logobserver.LineConsumerLogObserver(self._log_consumer))

    # returns (message type, path, line) tuple if line has been matched, or None otherwise
    def _match_line(self, line):
        m = self._default_2_0_0_line_re.match(line)
        if m:
            try:
                line_int = int(m.group('line'))
            except ValueError:
                line_int = None
            return (m.group('errtype'), m.group('path'), line_int)

        m = self._parseable_line_re.match(line)
        if m:
            try:
                line_int = int(m.group('line'))
            except ValueError:
                line_int = None
            return (m.group('errtype'), m.group('path'), line_int)

        m = self._default_line_re.match(line)
        if m:
            return (m.group('errtype'), None, None)

        return None

    def _log_consumer(self):
        while True:
            stream, line = yield
            if stream == 'h':
                continue

            ret = self._match_line(line)
            if not ret:
                continue

            msgtype, path, line_number = ret

            assert msgtype in self._MESSAGES
            self.summaries[msgtype].append(line)
            self.counts[msgtype] += 1

            if self._store_results and path is not None:
                self.addTestResult(
                    self._result_setid, line, test_name=None, test_code_path=path, line=line_number
                )

    def getResultSummary(self):
        summary = ' '.join(self.descriptionDone)
        for msg, fullmsg in sorted(self._MESSAGES.items()):
            if self.counts[msg]:
                summary += f" {fullmsg}={self.counts[msg]}"

        if self.results != SUCCESS:
            summary += f' ({statusToString(self.results)})'

        return {'step': summary}

    @defer.inlineCallbacks
    def run(self):
        cmd = yield self.makeRemoteShellCommand()
        yield self.runCommand(cmd)

        stdio_log = yield self.getLog('stdio')
        yield stdio_log.finish()

        for msg, fullmsg in sorted(self._MESSAGES.items()):
            if self.counts[msg]:
                yield self.addCompleteLog(fullmsg, "\n".join(self.summaries[msg]))
            self.setProperty(f"pylint-{fullmsg}", self.counts[msg], 'Pylint')
        self.setProperty("pylint-total", sum(self.counts.values()), 'Pylint')

        if cmd.rc & (self.RC_FATAL | self.RC_ERROR | self.RC_USAGE):
            return FAILURE

        for msg in self._flunkingIssues:
            if msg in self.counts and self.counts[msg] > 0:
                return FAILURE
        if sum(self.counts.values()) > 0:
            return WARNINGS
        return SUCCESS

    @defer.inlineCallbacks
    def addTestResultSets(self):
        if not self._store_results:
            return
        self._result_setid = yield self.addTestResultSet('Pylint warnings', 'code_issue', 'message')


class Sphinx(buildstep.ShellMixin, buildstep.BuildStep):
    """A Step to build sphinx documentation"""

    name = "sphinx"
    description = "running sphinx"
    descriptionDone = "sphinx"

    haltOnFailure = True

    def __init__(
        self,
        sphinx_sourcedir='.',
        sphinx_builddir=None,
        sphinx_builder=None,
        sphinx='sphinx-build',
        tags=None,
        defines=None,
        strict_warnings=False,
        mode='incremental',
        **kwargs,
    ):
        if tags is None:
            tags = []

        if defines is None:
            defines = {}

        if sphinx_builddir is None:
            # Who the heck is not interested in the built doc ?
            config.error("Sphinx argument sphinx_builddir is required")

        if mode not in ('incremental', 'full'):
            config.error("Sphinx argument mode has to be 'incremental' or" + "'full' is required")

        self.success = False

        kwargs = self.setupShellMixin(kwargs)

        super().__init__(**kwargs)

        # build the command
        command = [sphinx]
        if sphinx_builder is not None:
            command.extend(['-b', sphinx_builder])

        for tag in tags:
            command.extend(['-t', tag])

        for key in sorted(defines):
            if defines[key] is None:
                command.extend(['-D', key])
            elif isinstance(defines[key], bool):
                command.extend(['-D', f'{key}={(defines[key] and 1) or 0}'])
            else:
                command.extend(['-D', f'{key}={defines[key]}'])

        if mode == 'full':
            command.extend(['-E'])  # Don't use a saved environment

        if strict_warnings:
            command.extend(['-W'])  # Convert warnings to errors

        command.extend([sphinx_sourcedir, sphinx_builddir])
        self.command = command

        self.addLogObserver('stdio', logobserver.LineConsumerLogObserver(self._log_consumer))

    _msgs = ('WARNING', 'ERROR', 'SEVERE')

    def _log_consumer(self):
        self.warnings = []
        next_is_warning = False

        while True:
            _, line = yield
            if line.startswith('build succeeded') or line.startswith('no targets are out of date.'):
                self.success = True
            elif line.startswith('Warning, treated as error:'):
                next_is_warning = True
            else:
                if next_is_warning:
                    self.warnings.append(line)
                    next_is_warning = False
                else:
                    for msg in self._msgs:
                        if msg in line:
                            self.warnings.append(line)

    def getResultSummary(self):
        summary = f'{self.name} {len(self.warnings)} warnings'

        if self.results != SUCCESS:
            summary += f' ({statusToString(self.results)})'

        return {'step': summary}

    @defer.inlineCallbacks
    def run(self):
        cmd = yield self.makeRemoteShellCommand()
        yield self.runCommand(cmd)

        stdio_log = yield self.getLog('stdio')
        yield stdio_log.finish()

        if self.warnings:
            yield self.addCompleteLog('warnings', "\n".join(self.warnings))

        self.setStatistic('warnings', len(self.warnings))

        if self.success:
            if not self.warnings:
                return SUCCESS
            return WARNINGS
        return FAILURE


class PythonVirtualEnv(buildstep.BuildStep):
    """A Step to setup a virtual env for the Build"""

    name: str = "python_venv"

    haltOnFailure = True
    flunkOnFailure = True
    warnOnWarnings = True

    def __init__(
        self,
        py_version: int | tuple[int, int] | None = None,
        **kwargs,
    ):
        super().__init__(**kwargs)

        self.py_version = py_version
        if not (
            py_version is None
            or isinstance(py_version, int)
            or (
                isinstance(py_version, tuple)
                and len(py_version) == 2
                and all(isinstance(v, int) for v in py_version)
            )
        ):
            config.error(
                "PythonVirtualEnv: 'py_version' argument must be one of "
                "None, PythonMajor (as int), or "
                "tuple(PythonMajor, PythonMinor) (with both int)"
            )

    @property
    def worker_is_win32(self) -> bool:
        return self.worker.win32_worker

    @property
    def python_version_str(self) -> str:
        if self.py_version is None:
            return ''

        if isinstance(self.py_version, int):
            return str(self.py_version)

        if isinstance(self.py_version, tuple):
            major, minor = self.py_version
            return f"{major}.{minor}"

        raise TypeError(f"py_version unrecognized type {type(self.py_version)}")

    @property
    def worker_python(self) -> list[str]:
        if self.worker_is_win32:
            if self.py_version is None:
                return ['py']
            else:
                return ['py', f"-{self.python_version_str}"]
        else:
            return [f'python{self.python_version_str}']

    @property
    def worker_python_bin_dirname(self) -> str:
        return 'Scripts' if self.worker_is_win32 else 'bin'

    def get_worker_tmp(self) -> str | None:
        assert self.build is not None
        assert self.worker is not None

        tmp_env_vars = ['TMPDIR']
        tmp_default: str | None = '/tmp'
        if self.worker_is_win32:
            tmp_env_vars = ['TMP', 'TEMP']
            tmp_default = None

        for env_var in tmp_env_vars:
            if value := self.build.env.get(env_var):
                return value
            if value := self.worker.worker_environ.get(env_var):
                return value

        return tmp_default

    async def create_venv(self) -> PurePath | None:
        tmp_dir = self.get_worker_tmp()
        if tmp_dir is None:
            return None

        assert self.build is not None
        assert self.worker is not None
        venv_path = self.worker.path_cls(
            tmp_dir,
            f"{self.build.buildid}_venv_{self.python_version_str}",
        )

        venv_cmd = remotecommand.RemoteShellCommand(
            workdir=self.workdir,
            command=[
                *self.worker_python,
                "-m",
                "venv",
                "--clear",
                venv_path,
            ],
        )
        await self.runCommand(venv_cmd)
        if venv_cmd.results() != SUCCESS:
            # try delete venv if anything was created just in case
            await self.runCommand(
                remotecommand.RemoteCommand(
                    'rmdir',
                    {'dir': venv_path},
                    ignore_updates=True,
                )
            )
            return None

        return venv_path

    async def run_async(self) -> int:
        venv_path = await self.create_venv()
        if venv_path is None:
            return FAILURE

        def _hide_step_if_not_successful(result: int, _step: buildstep.BuildStep) -> bool:
            return result == SUCCESS

        assert self.build is not None
        self.build.add_cleanup_steps([
            RemoveDirectory(
                name=f"{self.name}_cleanup",
                dir=venv_path,
                alwaysRun=True,
                hideStepIf=_hide_step_if_not_successful,
                haltOnFailure=False,
                flunkOnFailure=False,
                flunkOnWarnings=False,
                warnOnFailure=True,
                warnOnWarnings=True,
            )
        ])

        properties = self.getProperties()
        properties.setProperty('virtualenv_path', venv_path, source=self.name, runtime=True)

        assert self.worker is not None
        python_bin_path = self.worker.path_cls(venv_path, self.worker_python_bin_dirname)
        properties.setProperty(
            'virtualenv_bin_path',
            str(python_bin_path),
            source=self.name,
            runtime=True,
        )

        venv_python_bin = self.worker.path_module.join(python_bin_path, 'python')
        properties.setProperty('venv_python_bin', venv_python_bin, source=self.name, runtime=True)

        # set envvars for remaining steps
        self.build.env["VIRTUAL_ENV"] = venv_path

        if path := self.build.env.get("PATH"):
            # if BuilderConfig or another step set PATH, add to it
            if isinstance(path, Iterable) and not isinstance(path, str):
                self.build.env["PATH"] = [python_bin_path, *path]
            else:
                self.build.env["PATH"] = [python_bin_path, path]
        else:
            self.build.env["PATH"] = [python_bin_path, "${PATH}"]

        return SUCCESS

    def run(self):
        return defer.Deferred.fromCoroutine(self.run_async())
