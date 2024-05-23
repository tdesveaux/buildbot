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

import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from twisted.trial import unittest


TEST_GIT_REPO_PATH = (Path(__file__).parent.parent / "test_git_repo").absolute()

# generated with `git -C {TEST_GIT_REPO_PATH} log --all --graph --pretty=oneline --decorate`
TEST_REPO_STATE = """\
*   c413927b8e2c915bed340ce5325ab32f6c9ab9d5 (HEAD -> main) Merge branch 'feature/1'
|\\
| * b692c76ebb10c797745330c92de68a11b2d5d413 (feature/1) Feature 1
* | d949729950f7476ee89173865cf4fa62449d15d3 (fix/1) Fix 1
|/
* c228e0bf59c31845635f0c2bc4cdb709ee8badfa Initial
"""


class RealGitRepositoryMixin:
    REMOTE_PATH = TEST_GIT_REPO_PATH
    REPOSITORY_STATE = TEST_REPO_STATE

    def git_bin(self):
        return shutil.which('git')

    def get_repository_state(self, git_bin: str = 'git') -> tuple[list[str], list[str]]:
        """Returns a tuple of current state of test repository, and expected state"""
        log_output = subprocess.check_output(
            [
                git_bin,
                '-C',
                str(self.REMOTE_PATH),
                'log',
                '--all',
                '--graph',
                '--pretty=oneline',
                '--decorate',
            ],
            text=True,
        )

        return (
            [line.strip() for line in log_output.splitlines()],
            [line.strip() for line in self.REPOSITORY_STATE.splitlines()],
        )

    def assert_repository_expecteds_state(
        self, testcase: unittest.TestCase, git_bin: str = 'git'
    ) -> None:
        testcase.assertEqual(*self.get_repository_state(git_bin=git_bin))
