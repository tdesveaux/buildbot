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

import base64
import functools
from typing import TYPE_CHECKING
from typing import Any

import msgpack
from autobahn.twisted.websocket import WebSocketServerFactory
from autobahn.twisted.websocket import WebSocketServerProtocol
from autobahn.websocket.types import ConnectionDeny
from twisted.internet import defer
from twisted.python import log

from buildbot.util import deferwaiter
from buildbot.util.twisted import any_to_async
from buildbot.util.twisted import async_to_deferred
from buildbot.worker.protocols.manager.base import BaseDispatcher
from buildbot.worker.protocols.manager.base import BaseManager

if TYPE_CHECKING:
    from collections.abc import Coroutine
    from typing import Any
    from typing import Callable
    from typing import TypeVar

    from autobahn.websocket.types import ConnectionRequest
    from twisted.internet.defer import Deferred
    from twisted.internet.protocol import ServerFactory

    from buildbot.worker.protocols.base import FileReaderImpl
    from buildbot.worker.protocols.base import FileWriterImpl
    from buildbot.worker.protocols.base import RemoteCommandImpl
    from buildbot.worker.protocols.msgpack import Connection

    _T = TypeVar('_T')


class ConnectioLostError(Exception):
    pass


class RemoteWorkerError(Exception):
    pass


def decode_http_authorization_header(value: str) -> tuple[str, str]:
    if value[:5] != 'Basic':
        raise ValueError("Value should always start with 'Basic'")

    credentials_str = base64.b64decode(value[6:]).decode()
    if ':' not in credentials_str:
        raise ValueError("String of credentials should always have a colon.")

    username, password = credentials_str.split(':', maxsplit=1)
    return (username, password)


def encode_http_authorization_header(name: bytes, password: bytes) -> str:
    if b":" in name:
        raise ValueError("Username is not allowed to contain a colon.")
    userpass = name + b':' + password
    return 'Basic ' + base64.b64encode(userpass).decode()


async def _run_with_mapped_command(
    protocol: BuildbotWebSocketServerProtocol,
    map: dict[str, _T],
    func: Callable[
        [BuildbotWebSocketServerProtocol, _T, dict],
        Coroutine[Any, Any, None],
    ],
    msg: dict,
) -> None:
    try:
        protocol.ensure_msg_keys(msg, 'command_id')
        command_obj = map.get(msg['command_id'])
        if command_obj is None:
            raise KeyError('unknown "command_id"')

        await func(protocol, command_obj, msg)
    except Exception as e:
        protocol.send_response_msg(msg, result=str(e), is_exception=True)
        return

    protocol.send_response_msg(msg, result=None, is_exception=False)


def with_command(
    func: Callable[
        [BuildbotWebSocketServerProtocol, RemoteCommandImpl, dict],
        Coroutine[Any, Any, None],
    ],
) -> Callable[
    [BuildbotWebSocketServerProtocol, dict],
    Coroutine[Any, Any, None],
]:
    @functools.wraps(func)
    async def wrapper_with_command(protocol: BuildbotWebSocketServerProtocol, msg: dict) -> None:
        await _run_with_mapped_command(
            protocol,
            protocol.command_id_to_command_map,
            func,
            msg,
        )

    return wrapper_with_command


def with_reader(
    func: Callable[
        [BuildbotWebSocketServerProtocol, FileReaderImpl, dict],
        Coroutine[Any, Any, None],
    ],
) -> Callable[
    [BuildbotWebSocketServerProtocol, dict],
    Coroutine[Any, Any, None],
]:
    @functools.wraps(func)
    async def wrapper_with_command(protocol: BuildbotWebSocketServerProtocol, msg: dict) -> None:
        await _run_with_mapped_command(
            protocol,
            protocol.command_id_to_reader_map,
            func,
            msg,
        )

    return wrapper_with_command


def with_writer(
    func: Callable[
        [BuildbotWebSocketServerProtocol, FileWriterImpl, dict],
        Coroutine[Any, Any, None],
    ],
) -> Callable[
    [BuildbotWebSocketServerProtocol, dict],
    Coroutine[Any, Any, None],
]:
    @functools.wraps(func)
    async def wrapper_with_command(protocol: BuildbotWebSocketServerProtocol, msg: dict) -> None:
        await _run_with_mapped_command(
            protocol,
            protocol.command_id_to_writer_map,
            func,
            msg,
        )

    return wrapper_with_command


class BuildbotWebSocketServerProtocol(WebSocketServerProtocol):
    debug = True

    def __init__(self) -> None:
        super().__init__()
        self.seq_num_to_waiters_map: dict[int, Deferred[Any]] = {}
        self.connection: Connection | None = None
        self.worker_name: str | None = None
        self._deferwaiter = deferwaiter.DeferWaiter()

        self._op_handlers: dict[str, Callable[[dict], defer.Deferred[None]]] = {
            "update": self.call_update,
            "update_upload_file_write": self.call_update_upload_file_write,
            "update_upload_file_close": self.call_update_upload_file_close,
            "update_upload_file_utime": self.call_update_upload_file_utime,
            "update_read_file": self.call_update_read_file,
            "update_read_file_close": self.call_update_read_file_close,
            "update_upload_directory_unpack": self.call_update_upload_directory_unpack,
            "update_upload_directory_write": self.call_update_upload_directory_write,
            "complete": self.call_complete,
        }

    def get_dispatcher(self) -> Dispatcher:
        # This is an instance of class msgpack.Dispatcher set in Dispatcher.__init__().
        # self.factory is set on the protocol instance when creating it in Twisted internals
        assert self.factory is not None
        return self.factory.buildbot_dispatcher

    @async_to_deferred
    async def onOpen(self) -> None:
        if self.debug:
            log.msg("WebSocket connection open.")
        self.seq_number = 0
        self.command_id_to_command_map: dict[str, RemoteCommandImpl] = {}
        self.command_id_to_reader_map: dict[str, FileReaderImpl] = {}
        self.command_id_to_writer_map: dict[str, FileWriterImpl] = {}
        await self.initialize()

    def maybe_log_worker_to_master_msg(self, message: dict[str, Any]) -> None:
        if self.debug:
            log.msg("WORKER -> MASTER message: ", message)

    def maybe_log_master_to_worker_msg(self, message: dict[str, Any]) -> None:
        if self.debug:
            log.msg("MASTER -> WORKER message: ", message)

    def ensure_msg_keys(self, msg: dict[str, Any], *keys: str) -> None:
        for k in keys:
            if k not in msg:
                raise KeyError(f'message did not contain obligatory "{k}" key')

    @async_to_deferred
    async def initialize(self) -> None:
        try:
            dispatcher = self.get_dispatcher()
            async with dispatcher.master.initLock:
                if self.worker_name in dispatcher.users:
                    _, afactory = dispatcher.users[self.worker_name]
                    self.connection = await any_to_async(afactory(self, self.worker_name))
                    await self.connection.attached(self)
                else:
                    self.sendClose()
        except Exception as e:
            log.msg(f"Connection opening failed: {e}")
            self.sendClose()

    @async_to_deferred
    @with_command
    async def call_update(self, command: RemoteCommandImpl, msg: dict) -> None:
        self.ensure_msg_keys(msg, 'args')
        await any_to_async(command.remote_update_msgpack(msg['args']))

    @async_to_deferred
    @with_command
    async def call_complete(self, command: RemoteCommandImpl, msg: dict) -> None:
        self.ensure_msg_keys(msg, 'args')
        await any_to_async(command.remote_complete(msg['args']))

        command_id = msg['command_id']
        self.command_id_to_command_map.pop(command_id)
        self.command_id_to_reader_map.pop(command_id, None)
        self.command_id_to_writer_map.pop(command_id, None)

    @async_to_deferred
    @with_writer
    async def call_update_upload_file_write(self, file_writer: FileWriterImpl, msg: dict) -> None:
        self.ensure_msg_keys(msg, 'args')
        await any_to_async(file_writer.remote_write(msg['args']))

    @async_to_deferred
    @with_writer
    async def call_update_upload_file_utime(self, file_writer: FileWriterImpl, msg: dict) -> None:
        self.ensure_msg_keys(msg, 'access_time', 'modified_time')
        await any_to_async(file_writer.remote_utime('access_time', 'modified_time'))

    @async_to_deferred
    @with_writer
    async def call_update_upload_file_close(self, file_writer: FileWriterImpl, msg: dict) -> None:
        await any_to_async(file_writer.remote_close())

    @async_to_deferred
    @with_reader
    async def call_update_read_file(self, file_reader: FileReaderImpl, msg: dict) -> None:
        self.ensure_msg_keys(msg, 'length')
        await any_to_async(file_reader.remote_read(msg['length']))

    @async_to_deferred
    @with_reader
    async def call_update_read_file_close(self, file_reader: FileReaderImpl, msg: dict) -> None:
        await any_to_async(file_reader.remote_close())

    @async_to_deferred
    @with_writer
    async def call_update_upload_directory_unpack(
        self, directory_writer: FileWriterImpl, msg: dict
    ) -> None:
        await any_to_async(directory_writer.remote_unpack())

    @async_to_deferred
    @with_writer
    async def call_update_upload_directory_write(
        self, directory_writer: FileWriterImpl, msg: dict
    ) -> None:
        self.ensure_msg_keys(msg, 'args')
        await any_to_async(directory_writer.remote_write(msg['args']))

    def send_response_msg(
        self,
        msg: dict[str, Any],
        result: str | None,
        is_exception: bool,
    ) -> None:
        dict_output = {'op': 'response', 'seq_number': msg['seq_number'], 'result': result}
        if is_exception:
            dict_output['is_exception'] = True

        self.maybe_log_master_to_worker_msg(dict_output)
        payload = msgpack.packb(dict_output, use_bin_type=True)

        self.sendMessage(payload, isBinary=True)

    def onMessage(self, payload: bytes, isBinary: bool) -> None:
        if not isBinary:
            name = self.worker_name if self.worker_name is not None else '<???>'
            log.msg(f'Message type from worker {name} unsupported')
            return

        msg = msgpack.unpackb(payload, raw=False)
        self.maybe_log_worker_to_master_msg(msg)

        if 'seq_number' not in msg or 'op' not in msg:
            log.msg(f'Invalid message from worker: {msg}')
            return

        msg_op = msg['op']

        if msg_op != "response" and self.connection is None:
            self.send_response_msg(msg, "Worker not authenticated.", is_exception=True)
            return

        msg_handler = self._op_handlers.get(msg_op)
        if msg_handler is not None:
            self._deferwaiter.add(msg_handler(msg))
        elif msg_op == "response":
            seq_number = msg['seq_number']
            # stop waiting for a response of this command
            waiter = self.seq_num_to_waiters_map.pop(seq_number)
            if "is_exception" in msg:
                waiter.errback(RemoteWorkerError(msg['result']))
            else:
                waiter.callback(msg['result'])
        else:
            self.send_response_msg(msg, f"Command {msg_op} does not exist.", is_exception=True)

    @async_to_deferred
    async def get_message_result(self, msg: dict[str, Any]) -> Any:
        if msg['op'] != 'print' and msg['op'] != 'get_worker_info' and self.connection is None:
            raise ConnectioLostError("No worker connection")

        msg['seq_number'] = self.seq_number

        self.maybe_log_master_to_worker_msg(msg)

        object = msgpack.packb(msg, use_bin_type=True)
        d: Deferred[Any] = defer.Deferred()
        self.seq_num_to_waiters_map[self.seq_number] = d

        self.seq_number = self.seq_number + 1
        self.sendMessage(object, isBinary=True)
        return await d

    @async_to_deferred
    async def onConnect(self, request: ConnectionRequest) -> None:
        if self.debug:
            log.msg(f"Client connecting: {request.peer}")

        value = request.headers.get('authorization')
        if value is None:
            raise ConnectionDeny(401, "Unauthorized")

        try:
            username, password = decode_http_authorization_header(value)
        except Exception as e:
            raise ConnectionDeny(400, "Bad request") from e

        try:
            dispatcher = self.get_dispatcher()
            async with dispatcher.master.initLock:
                if username in dispatcher.users:
                    pwd, _ = dispatcher.users[username]
                    if pwd == password:
                        self.worker_name = username
                        authentication = True
                    else:
                        authentication = False
                else:
                    authentication = False
        except Exception as e:
            raise RuntimeError("Internal error") from e

        if not authentication:
            raise ConnectionDeny(401, "Unauthorized")

    def onClose(self, wasClean: bool, code: int | None, reason: str) -> None:
        if self.debug:
            log.msg(f"WebSocket connection closed: {reason}")
        # stop waiting for the responses of all commands
        for d in self.seq_num_to_waiters_map.values():
            d.errback(ConnectioLostError("Connection lost"))
        self.seq_num_to_waiters_map.clear()

        if self.connection is not None:
            defer.maybeDeferred(self.connection.detached, self)


class Dispatcher(BaseDispatcher):
    DUMMY_PORT = 1

    def _create_server_factory(self, config_port: str | int) -> ServerFactory:
        try:
            port = int(config_port)
        except ValueError as e:
            raise ValueError(f'portstr unsupported: {config_port}') from e

        # Autobahn does not support zero port meaning to pick whatever port number is free, so
        # we work around this by setting the port to nonzero value and resetting the value once
        # the port is known. This is possible because Autobahn doesn't do anything with the port
        # during the listening setup.
        self._zero_port = port == 0
        if self._zero_port:
            port = self.DUMMY_PORT

        serverFactory = WebSocketServerFactory(f"ws://0.0.0.0:{port}")
        serverFactory.buildbot_dispatcher = self
        serverFactory.protocol = BuildbotWebSocketServerProtocol
        return serverFactory

    @async_to_deferred
    async def startService(self) -> None:
        await super().startService()

        if self._zero_port:
            # Check that websocket port is actually stored into the port attribute, as we're
            # relying on undocumented behavior.
            if self.serverFactory.port != self.DUMMY_PORT:  # type: ignore[attr-defined]
                raise RuntimeError("Expected websocket port to be set to dummy port")
            assert self.bound_port is not None
            self.serverFactory.port = self.bound_port  # type: ignore[attr-defined]


class MsgManager(BaseManager[Dispatcher]):
    def __init__(self) -> None:
        super().__init__('msgmanager')

    dispatcher_class = Dispatcher
