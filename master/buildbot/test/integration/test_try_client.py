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

import inspect
import os
from typing import Any
from typing import Callable
from typing import Coroutine
from typing import TypeVar
from unittest import mock

from twisted.internet import defer
from twisted.internet import reactor
from twisted.python import log
from twisted.python.filepath import FilePath

from buildbot import util
from buildbot.clients import tryclient
from buildbot.master import BuildMaster
from buildbot.schedulers import trysched
from buildbot.test.util import www
from buildbot.test.util.integration import RunMasterBase
from buildbot.util.twisted import async_to_deferred

_T = TypeVar('_T')


# wait for some asynchronous result
async def waitFor(fn: Callable[[], defer.Deferred[_T] | Coroutine[Any, Any, _T] | _T]) -> None:
    while True:
        call: defer.Deferred[_T] | Coroutine[Any, Any, _T] | _T = fn()
        if inspect.isawaitable(call) or isinstance(call, defer.Deferred):
            res = await call
        else:
            res = call

        if res:
            break
        await util.asyncSleep(0.01)


class _TrySchedulersBase(RunMasterBase, www.RequiresWwwMixin):
    output: list[str]
    serverPort: str
    master: BuildMaster | None
    sch: trysched.TryBase | None

    def setUp(self) -> None:
        self.master = None
        self.sch = None

        def spawnProcess(pp, executable, args, environ):
            tmpfile = os.path.join(self.jobdir, 'tmp', 'testy')
            newfile = os.path.join(self.jobdir, 'new', 'testy')
            with open(tmpfile, "w", encoding='utf-8') as f:
                f.write(pp.job)
            os.rename(tmpfile, newfile)
            log.msg(f"wrote jobfile {newfile}")
            # get the scheduler to poll this directory now
            assert isinstance(self.sch, trysched.Try_Jobdir)
            d = self.sch.watcher.poll()
            d.addErrback(log.err, 'while polling')

            @d.addCallback
            def finished(_):
                st = mock.Mock()
                st.value.signal = None
                st.value.exitCode = 0
                pp.processEnded(st)

        self.patch(reactor, 'spawnProcess', spawnProcess)

        self.sourcestamp = tryclient.SourceStamp(branch='br', revision='rr', patch=(0, '++--'))

        def getSourceStamp(vctype, treetop, branch=None, repository=None):
            return defer.succeed(self.sourcestamp)

        self.patch(tryclient, 'getSourceStamp', getSourceStamp)

        self.output = []

        # stub out printStatus, as it's timing-based and thus causes
        # occasional test failures.
        self.patch(tryclient.Try, 'printStatus', lambda _: None)

        def output(*msg):
            msg = ' '.join(map(str, msg))
            log.msg(f"output: {msg}")
            self.output.append(msg)

        self.patch(tryclient, 'output', output)

    def setupJobdir(self):
        jobdir = FilePath(self.mktemp())
        jobdir.createDirectory()
        self.jobdir = jobdir.path
        for sub in 'new', 'tmp', 'cur':
            jobdir.child(sub).createDirectory()
        return self.jobdir

    async def setup_config(self, extra_config) -> None:
        c: dict[str, Any] = {}
        from buildbot.config import BuilderConfig
        from buildbot.process import results
        from buildbot.process.buildstep import BuildStep
        from buildbot.process.factory import BuildFactory

        class MyBuildStep(BuildStep):
            def run(self):
                return results.SUCCESS

        c['change_source'] = []
        c['schedulers'] = []  # filled in above
        f1 = BuildFactory()
        f1.addStep(MyBuildStep(name='one'))
        f1.addStep(MyBuildStep(name='two'))
        c['builders'] = [
            BuilderConfig(name="a", workernames=["local1"], factory=f1),
        ]
        c['title'] = "test"
        c['titleURL'] = "test"
        c['buildbotURL'] = "http://localhost:8010/"
        c['mq'] = {'debug': True}
        # test wants to influence the config, but we still return a new config
        # each time
        c.update(extra_config)
        await self.setup_master(c)

    async def startMaster(self, sch: trysched.TryBase) -> None:
        assert isinstance(sch, trysched.TryBase), f"{type(sch)=}"
        extra_config = {
            'schedulers': [sch],
        }
        self.sch = sch

        await self.setup_config(extra_config)

        # wait until the scheduler is active
        await waitFor(lambda: self.sch is not None and self.sch.active)

        # and, for Try_Userpass, until it's registered its port
        if isinstance(self.sch, trysched.Try_Userpass):

            def getSchedulerPort() -> bool:
                assert self.sch is not None and isinstance(self.sch, trysched.Try_Userpass)
                if not self.sch.registrations:
                    return False
                self.serverPort = self.sch.registrations[0].getPort()
                log.msg(f"Scheduler registered at port {self.serverPort}")
                return True

            await waitFor(getSchedulerPort)

    async def runClient(self, config) -> None:
        self.clt = tryclient.Try(config)
        await self.clt.run_impl()

    async def _base_run_client(
        self,
        run_client_args: dict[str, Any],
        expected_output: list[str],
    ) -> list:
        await self.runClient({
            'username': 'u',
            'passwd': b'p',
            **run_client_args,
        })
        self.assertEqual(
            self.output,
            expected_output,
        )
        assert self.master is not None
        return await self.master.db.buildsets.getBuildsets()


class TrySchedulerUserPass(_TrySchedulersBase):
    async def _base_run_client_userpass(
        self,
        run_client_args: dict[str, Any],
        expected_output: list[str],
    ) -> list:
        await self.startMaster(
            trysched.Try_Userpass(
                'try',
                ['a'],
                0,
                [('u', b'p')],
            )
        )
        return await self._base_run_client(
            run_client_args={
                'connect': 'pb',
                'master': f'127.0.0.1:{self.serverPort}',
                **run_client_args,
            },
            expected_output=expected_output,
        )

    @async_to_deferred
    async def test_userpass_no_wait(self):
        buildsets = await self._base_run_client_userpass(
            run_client_args={},
            expected_output=[
                "using 'pb' connect method",
                'job created',
                'Delivering job; comment= None',
                'job has been delivered',
                'not waiting for builds to finish',
            ],
        )
        self.assertEqual(len(buildsets), 1)

    async def test_userpass_wait(self) -> None:
        buildsets = await self._base_run_client_userpass(
            run_client_args={
                'wait': True,
            },
            expected_output=[
                "using 'pb' connect method",
                'job created',
                'Delivering job; comment= None',
                'job has been delivered',
                'All Builds Complete',
                'a: success (build successful)',
            ],
        )
        self.assertEqual(len(buildsets), 1)

    async def test_userpass_wait_bytes(self) -> None:
        self.sourcestamp = tryclient.SourceStamp(branch=b'br', revision=b'rr', patch=(0, b'++--'))

        buildsets = await self._base_run_client_userpass(
            run_client_args={
                'wait': True,
            },
            expected_output=[
                "using 'pb' connect method",
                'job created',
                'Delivering job; comment= None',
                'job has been delivered',
                'All Builds Complete',
                'a: success (build successful)',
            ],
        )
        self.assertEqual(len(buildsets), 1)

    async def test_userpass_wait_dryrun(self) -> None:
        buildsets = await self._base_run_client_userpass(
            run_client_args={
                'wait': True,
                'dryrun': True,
            },
            expected_output=[
                "using 'pb' connect method",
                'job created',
                'Job:\n'
                '\tRepository: \n'
                '\tProject: \n'
                '\tBranch: br\n'
                '\tRevision: rr\n'
                '\tBuilders: None\n'
                '++--',
                'job has been delivered',
                'All Builds Complete',
            ],
        )
        self.assertEqual(len(buildsets), 0)

    async def test_userpass_list_builders(self) -> None:
        buildsets = await self._base_run_client_userpass(
            run_client_args={
                'get-builder-names': True,
            },
            expected_output=[
                "using 'pb' connect method",
                'The following builders are available for the try scheduler: ',
                'a',
            ],
        )
        self.assertEqual(len(buildsets), 0)


class TrySchedulerJobDir(_TrySchedulersBase):
    async def _base_run_client_jobdir(
        self,
        run_client_args: dict[str, Any],
        expected_output: list[str],
    ) -> list:
        jobdir = self.setupJobdir()
        await self.startMaster(trysched.Try_Jobdir('try', ['a'], jobdir))
        return await self._base_run_client(
            run_client_args={
                'connect': 'ssh',
                'master': '127.0.0.1',
                **run_client_args,
            },
            expected_output=expected_output,
        )

    async def test_jobdir_no_wait(self) -> None:
        buildsets = await self._base_run_client_jobdir(
            run_client_args={
                'builders': 'a',  # appears to be required for ssh
            },
            expected_output=[
                "using 'ssh' connect method",
                'job created',
                'job has been delivered',
                'not waiting for builds to finish',
            ],
        )
        self.assertEqual(len(buildsets), 1)

    async def test_jobdir_wait(self) -> None:
        buildsets = await self._base_run_client_jobdir(
            run_client_args={
                'wait': True,
                'builders': 'a',  # appears to be required for ssh
            },
            expected_output=[
                "using 'ssh' connect method",
                'job created',
                'job has been delivered',
                'waiting for builds with ssh is not supported',
            ],
        )
        self.assertEqual(len(buildsets), 1)
