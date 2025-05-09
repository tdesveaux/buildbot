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

from twisted.internet import defer
from twisted.trial import unittest

from buildbot_worker.commands.base import Command
from buildbot_worker.test.util.command import CommandTestMixin

# set up a fake Command subclass to test the handling in Command.  Think of
# this as testing Command's subclassability.


class DummyCommand(Command):
    def setup(self, args):
        self.setup_done = True
        self.interrupted = False
        self.started = False

    def start(self):
        self.started = True
        data = []
        for key, value in self.args.items():
            data.append((key, value))
        self.sendStatus(data)
        self.cmd_deferred = defer.Deferred()
        return self.cmd_deferred

    def interrupt(self):
        self.interrupted = True
        self.finishCommand()

    def finishCommand(self):
        d = self.cmd_deferred
        self.cmd_deferred = None
        d.callback(None)

    def failCommand(self):
        d = self.cmd_deferred
        self.cmd_deferred = None
        d.errback(RuntimeError("forced failure"))


class DummyArgsCommand(DummyCommand):
    requiredArgs = ['workdir']


class TestDummyCommand(CommandTestMixin, unittest.TestCase):
    def setUp(self):
        self.setUpCommand()

    def assertState(self, setup_done, running, started, interrupted, msg=None):
        self.assertEqual(
            {
                'setup_done': self.cmd.setup_done,
                'running': self.cmd.running,
                'started': self.cmd.started,
                'interrupted': self.cmd.interrupted,
            },
            {
                'setup_done': setup_done,
                'running': running,
                'started': started,
                'interrupted': interrupted,
            },
            msg,
        )

    @defer.inlineCallbacks
    def test_run(self):
        cmd = self.make_command(DummyCommand, {'stdout': 'yay'})
        self.assertState(True, False, False, False, "setup called by constructor")

        # start the command
        d = self.run_command()
        self.assertState(True, True, True, False, "started and running both set")

        # allow the command to finish and check the result
        cmd.finishCommand()

        yield d
        self.assertState(True, False, True, False, "started and not running when done")
        self.assertUpdates([('stdout', 'yay')], "updates processed")

    @defer.inlineCallbacks
    def test_run_failure(self):
        cmd = self.make_command(DummyCommand, {})
        self.assertState(True, False, False, False, "setup called by constructor")

        # start the command
        d = self.run_command()
        self.assertState(True, True, True, False, "started and running both set")

        # fail the command with an exception, and check the result
        cmd.failCommand()

        with self.assertRaises(RuntimeError):
            yield d
        self.assertState(True, False, True, False, "started and not running when done")
        self.assertUpdates([], "updates processed")

    def test_run_interrupt(self):
        cmd = self.make_command(DummyCommand, {})
        self.assertState(True, False, False, False, "setup called by constructor")

        # start the command
        d = self.run_command()
        self.assertState(True, True, True, False, "started and running both set")

        # interrupt the command
        cmd.doInterrupt()
        self.assertTrue(cmd.interrupted)

        def check(_):
            self.assertState(True, False, True, True, "finishes with interrupted set")

        d.addCallback(check)
        return d

    def test_required_args(self):
        self.make_command(DummyArgsCommand, {'workdir': '.'})
        try:
            self.make_command(DummyArgsCommand, {'stdout': 'boo'})
        except ValueError:
            return
        self.fail("Command was supposed to raise ValueError when missing args")
