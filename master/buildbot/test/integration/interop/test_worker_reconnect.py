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

from twisted.internet import defer

from buildbot.process.buildstep import BuildStep
from buildbot.process.results import SUCCESS
from buildbot.test.util.integration import RunMasterBase


class DisconnectingStep(BuildStep):
    disconnection_list: list[DisconnectingStep] = []

    def run(self):
        self.disconnection_list.append(self)
        assert self.worker.conn.get_peer().startswith("127.0.0.1:")
        if len(self.disconnection_list) < 2:
            self.worker.disconnect()
        return SUCCESS


class WorkerReconnectPb(RunMasterBase):
    """integration test for testing worker disconnection and reconnection"""

    proto = "pb"

    @defer.inlineCallbacks
    def setup_config(self):
        c = {}
        from buildbot.config import BuilderConfig
        from buildbot.plugins import schedulers
        from buildbot.process.factory import BuildFactory

        c['schedulers'] = [
            schedulers.AnyBranchScheduler(name="sched", builderNames=["testy"]),
            schedulers.ForceScheduler(name="force", builderNames=["testy"]),
        ]

        f = BuildFactory()
        f.addStep(DisconnectingStep())
        c['builders'] = [BuilderConfig(name="testy", workernames=["local1"], factory=f)]
        yield self.setup_master(c)

    @defer.inlineCallbacks
    def test_eventually_reconnect(self):
        DisconnectingStep.disconnection_list = []
        yield self.setup_config()

        build = yield self.doForceBuild()
        self.assertEqual(build['buildid'], 2)
        self.assertEqual(len(DisconnectingStep.disconnection_list), 2)


class WorkerReconnectMsgPack(WorkerReconnectPb):
    proto = "msgpack"
