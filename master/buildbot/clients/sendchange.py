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

from typing import TYPE_CHECKING
from typing import cast

from twisted.cred import credentials
from twisted.internet import defer
from twisted.internet import reactor
from twisted.spread import pb

from buildbot.util import unicode2bytes

if TYPE_CHECKING:
    from twisted.internet.interfaces import IReactorTCP

    from buildbot.util.twisted import InlineCallbacksType


class Sender:
    def __init__(
        self,
        master: str,
        auth: tuple[str, str] = ('change', 'changepw'),
        encoding: str = 'utf8',
    ) -> None:
        self.username = unicode2bytes(auth[0])
        self.password = unicode2bytes(auth[1])
        self.host, port = master.split(":")
        self.port = int(port)
        self.encoding = encoding

    @defer.inlineCallbacks
    def send(
        self,
        branch: str | bytes,
        revision: str | bytes,
        comments: str | bytes,
        files: list[bytes] | tuple[str, ...] | list[str],
        who: str | bytes | None = None,
        category: str | bytes | None = None,
        when: int | None = None,
        properties: dict[str, str] | dict[bytes, str] | None = None,
        repository: str | bytes = '',
        vc: str | None = None,
        project: str | bytes = '',
        revlink: str | bytes = '',
        codebase: str | None = None,
    ) -> InlineCallbacksType[None]:
        if properties is None:
            properties = {}

        change = {
            'project': project,
            'repository': repository,
            'who': who,
            'files': [
                file.decode(self.encoding, 'replace') if isinstance(file, bytes) else file
                for file in files
            ],
            'comments': comments,
            'branch': branch,
            'revision': revision,
            'category': category,
            'when': when,
            'properties': properties,
            'revlink': revlink,
            'src': vc,
        }

        # codebase is only sent if set; this won't work with masters older than
        # 0.8.7
        if codebase:
            change['codebase'] = codebase

        for key, value in change.items():
            if isinstance(value, bytes):
                change[key] = value.decode(self.encoding, 'replace')

        f = pb.PBClientFactory()
        d = f.login(credentials.UsernamePassword(self.username, self.password))
        cast("IReactorTCP", reactor).connectTCP(self.host, self.port, f)

        remote = yield d
        yield remote.callRemote('addChange', change)
        yield remote.broker.transport.loseConnection()
