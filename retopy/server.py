#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2015 Timu EREN
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import socket

from tornado.tcpserver import TCPServer
from tornado import gen
from tornado.escape import native_str
from tornado.log import gen_log, app_log
from tornado import iostream
from tornado.http1connection import _QuietException, _ExceptionLoggingContext
from tornado.concurrent import Future
from tornado import stack_context

from command import HelpCommandHandler, Command, \
    CommandSpec, CommandNotFoundHandler, \
    _find_commands_in_handler, CommandsCommandHandler


class RetopyServer(TCPServer):
    """Basic TCPServer implementation
    """

    @gen.coroutine
    def close_all_connections(self):
        while self._connections:
            # Peek at an arbitrary element of the set
            conn = next(iter(self._connections))
            yield conn.close()

    def __init__(self, application, io_loop=None, ssl_options=None,
                 max_buffer_size=None, read_chunk_size=None, **params):
        self.application = application
        self.params = params
        # holds connections
        self._connections = set()
        TCPServer.__init__(self,
                           io_loop=io_loop, ssl_options=ssl_options,
                           max_buffer_size=max_buffer_size, read_chunk_size=read_chunk_size)

    def handle_stream(self, stream, address):
        context = ConnectionContext(stream, address)
        conn = ServerConnection(stream, context, self.params)
        self._connections.add(conn)

        # start proccessing request
        conn.start_serving(self)

    def on_close(self, server_connection):
        self._connections.remove(server_connection)

    def start_request(self, server_connection, connection):
        return _RequestAdapter(self, server_connection, connection)


class _RequestAdapter(object):
    def __init__(self, retopy_server, server_connection, connection):
        self.server = retopy_server
        self.server_connection = server_connection
        self.connection = connection
        self.executor = retopy_server.application.start_request(server_connection, connection)

    def command_received(self, command):
        self.executor.command_received(command)
        return self.executor.get_command_arguments()

    def parameters_received(self, parameters):
        self.executor.parameters_received(parameters)

    def headers_received(self, headers):
        self.executor.headers_received(headers)

    def finish(self):
        self.executor.finish()


class ConnectionContext(object):
    def __init__(self, stream, address):
        self.address = address
        self.headers = {}
        # Save the socket's address family now so we know how to
        # interpret self.address even after the stream is closed
        # and its socket attribute replaced with None.
        if stream.socket is not None:
            self.address_family = stream.socket.family
        else:
            self.address_family = None
        # In HTTPServerRequest we want an IP, not a full socket address.
        if (self.address_family in (socket.AF_INET, socket.AF_INET6) and
                    address is not None):
            self.remote_ip = address[0]
        else:
            # Unix (or other) socket; fake the remote address.
            self.remote_ip = '0.0.0.0'

    def __str__(self):
        if self.address_family in (socket.AF_INET, socket.AF_INET6):
            return self.remote_ip
        elif isinstance(self.address, bytes):
            # Python 3 with the -bb option warns about str(bytes),
            # so convert it explicitly.
            # Unix socket addresses are str on mac but bytes on linux.
            return native_str(self.address)
        else:
            return str(self.address)

    def set_headers(self, headers):
        self.headers = headers

    def is_headers_received(self):
        return True if self.headers else False


class MalFormatInput(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


class ServerConnection(object):
    """Server connection object """

    def __init__(self, stream, context=None, params=None):
        """
        :arg stream: an `.IOStream`
        :arg context: an opaque application-defined object that is accessible
            as ``connection.context``
        """
        self.stream = stream
        self.context = context
        self._serving_future = None
        self.params = params or {}

    @gen.coroutine
    def close(self):
        """Closes the connection.

        Returns a `.Future` that resolves after the serving loop has exited.
        """
        self.stream.close()
        # Block until the serving loop is done, but ignore any exceptions
        # (start_serving is already responsible for logging them).
        try:
            yield self._serving_future
        except Exception:
            pass

    def start_serving(self, retopy_server):
        """Starts serving requests on this connection.

        :arg retopy_server: a `.RetopyServer instance`
        """
        self._serving_future = self._server_request_loop(retopy_server)
        # Register the future on the IOLoop so its errors get logged.
        self.stream.io_loop.add_future(self._serving_future,
                                       lambda f: f.result())

    @gen.coroutine
    def _server_request_loop(self, retopy_server):
        try:
            conn = RequestConnection(self.stream, self.context, self.params)
            request_adapter = retopy_server.start_request(self, conn)
            while True:
                try:
                    ret = yield conn.read_response(request_adapter)
                except (iostream.StreamClosedError,
                        iostream.UnsatisfiableReadError):
                    return
                except _QuietException:
                    # This exception was already logged.
                    conn.close()
                    return
                except Exception:
                    gen_log.error("Uncaught exception", exc_info=True)
                    conn.close()
                    return
                if not ret:
                    return
                yield gen.moment
        finally:
            retopy_server.on_close(self)


class RequestConnection(object):
    def __init__(self, stream, context, params):
        self.stream = stream
        self.context = context
        # connection parameters
        self.params = params
        self._write_callback = None
        self._write_future = None
        self._close_callback = None
        self._read_finished = False
        self._write_finished = False
        self._finish_future = None
        self._reset()
        self._clear_callbacks()
        # A Future for our outgoing writes, returned by IOStream.write.
        self._pending_write = None

    def close(self):
        if self.stream is not None:
            self.stream.close()
        self._clear_callbacks()
        if not self._finish_future.done():
            self._finish_future.set_result(None)

    def _clear_callbacks(self):
        """Clears the callback attributes.

        This allows the request handler to be garbage collected more
        quickly in CPython by breaking up reference cycles.
        """
        self._write_callback = None
        self._write_future = None
        self._close_callback = None
        if self.stream is not None:
            self.stream.set_close_callback(None)

    @property
    def headers_received(self):
        return self.context.is_headers_received()

    def set_headers(self, headers):
        self.context.set_headers(headers)

    @gen.coroutine
    def read_response(self, request_adapter):
        """
        bu method bölünerek istemci ile aralarında kullanılacak parametreler için handshake oluşturmalı
        bu işlemin ardından komutlar için dinlemeye devam etmeli.
        :param request_adapter:
        :return: future
        """
        try:
            if not self.headers_received:
                headers_future = self.stream.read_until_regex(b"\r\n",
                                                              max_bytes=self.params.get("max_header_size", 255))
                if self.params.get("header_timeout", None) is None:
                    headers = yield headers_future
                else:
                    try:
                        headers = yield gen.with_timeout(
                            self.stream.io_loop.time() + int(self.params.get("header_timeout")),
                            headers_future,
                            io_loop=self.stream.io_loop,
                            quiet_exceptions=iostream.StreamClosedError
                        )
                    except gen.TimeoutError:
                        self.close()
                        raise gen.Return(False)
                with _ExceptionLoggingContext(app_log):
                    future = request_adapter.headers_received(headers)
                    if future:
                        yield future
            # wait a command
            """from here to end it's from redis it self"""
            line = yield self.stream.read_until_regex(b"\r\n")
            line = iter(line)
            command = ""
            for char in line:
                if char in (" ", "\r", "\n", "\t", "\0"):
                    break
                command += char

            with _ExceptionLoggingContext(app_log):
                parameters = request_adapter.command_received(command)

            _count = 0
            params = {}
            if len(parameters) > 0:
                for char in line:
                    if char in (" ", "\t", "\n", "\r", "\v", "\f"):
                        continue
                    print char
                    in_quote = False
                    in_single_quote = False
                    current = ""
                    while True:
                        if in_quote:
                            if char == '\\':
                                try:
                                    c = line.next()
                                    if c not in ('n', 'r', 't', 'b', 'a'):
                                        char = c
                                    else:
                                        char = "\%s" % (c)
                                except StopIteration:
                                    raise MalFormatInput("Malformat input")
                                current += char
                            elif char == '"':
                                try:
                                    c = line.next()
                                    if c not in (" ", "\t", "\r", "\n", "\v", "\f"):
                                        raise MalFormatInput("Malformat input")
                                    break
                                except StopIteration:
                                    raise MalFormatInput("Malformat input")
                            else:
                                current += char
                        elif in_single_quote:
                            if char == '\\':
                                try:
                                    c = line.next()
                                    if c == '\'':
                                        char = "'"
                                    else:
                                        char = char + c
                                except StopIteration:
                                    raise MalFormatInput("Malformat input")
                                current += char
                            elif char == '\'':
                                try:
                                    c = line.next()
                                    if c not in (" ", "\t", "\r", "\n", "\v", "\f"):
                                        raise MalFormatInput("Malformat input")
                                    break
                                except StopIteration:
                                    raise MalFormatInput("Malformat input")
                            else:
                                current += char
                        else:
                            if char in (' ', '\n', '\r', '\t', '\0'):
                                break
                            elif char == '"':
                                in_quote = True
                            elif char == '\'':
                                in_single_quote = True
                            else:
                                current += char
                        try:
                            char = line.next()
                        except StopIteration:
                            break
                    if parameters[_count]["type"]:
                        try:
                            current = parameters[_count]["type"](current)
                        except TypeError:
                            raise MalFormatInput("%s type must be %s" % (parameters[_count]["name"],
                                                                         parameters[_count]["type"]))

                    arg_name = parameters[_count]["name"]
                    if arg_name not in params:
                        params[arg_name] = []
                    params[arg_name].append(current)
                    _count += 1

            with _ExceptionLoggingContext(app_log):
                parameter_future = request_adapter.parameters_received(params)
                if parameter_future is not None:
                    yield parameter_future

            self._read_finished = True
            if not self._write_finished:
                with _ExceptionLoggingContext(app_log):
                    request_adapter.finish()
            # If we're waiting for the application to produce an asynchronous
            # response, and we're not detached, register a close callback
            # on the stream (we didn't need one while we were reading)
            if (not self._finish_future.done() and
                        self.stream is not None and
                    not self.stream.closed()):
                self.stream.set_close_callback(self._on_connection_close)
                yield self._finish_future
            if self.stream is None:
                raise gen.Return(False)
            # after reading commands and writing response
            # we must reset read and write markers and futures
            self._reset()
        except Exception, e:
            self.close()
            raise gen.Return(False)
        raise gen.Return(True)

    def _reset(self):
        # _write_finished is set to True when finish() has been called,
        # i.e. there will be no more data sent.  Data may still be in the
        # stream's write buffer.
        self._write_finished = False
        # True when we have read the entire incoming body.
        self._read_finished = False
        # _finish_future resolves when all data has been written and flushed
        # to the IOStream.
        self._finish_future = Future()

    def _on_connection_close(self):
        # Note that this callback is only registered on the IOStream
        # when we have finished reading the request and are waiting for
        # the application to produce its response.
        if self._close_callback is not None:
            callback = self._close_callback
            self._close_callback = None
            callback()
        if not self._finish_future.done():
            self._finish_future.set_result(None)
        self._clear_callbacks()

    def write(self, chunk, callback=None):
        """
        For backwards compatibility is is allowed but deprecated to
        skip `write_headers` and instead call `write()` with a
        pre-encoded header block.
        """
        future = None
        if self.stream.closed():
            future = self._write_future = Future()
            self._write_future.set_exception(iostream.StreamClosedError())
            self._write_future.exception()
        else:
            if callback is not None:
                self._write_callback = stack_context.wrap(callback)
            else:
                future = self._write_future = Future()
            self._pending_write = self.stream.write(chunk)
            self._pending_write.add_done_callback(self._on_write_complete)
        return future

    def _on_write_complete(self, future):
        exc = future.exception()
        if exc is not None and not isinstance(exc, iostream.StreamClosedError):
            future.result()
        if self._write_callback is not None:
            callback = self._write_callback
            self._write_callback = None
            self.stream.io_loop.add_callback(callback)
        if self._write_future is not None:
            future = self._write_future
            self._write_future = None
            future.set_result(None)

    def finish(self):
        self._write_finished = True
        # No more data is coming, so instruct TCP to send any remaining
        # data immediately instead of waiting for a full packet or ack.
        self.stream.set_nodelay(True)
        if self._pending_write is None:
            self._finish_request(None)
        else:
            self._pending_write.add_done_callback(self._finish_request)

    def _finish_request(self, future):
        self._clear_callbacks()
        # Turn Nagle's algorithm back on, leaving the stream in its
        # default state for the next request.
        self.stream.set_nodelay(False)
        if not self._finish_future.done():
            self._finish_future.set_result(None)


class Application(object):
    def __init__(self, handlers=None, **settings):
        self.handlers = []
        self.settings = settings
        self.stats = {}

        if handlers:
            self.add_handlers(handlers)

        if self.settings.get("default_handlers", True):
            self.register_default_handlers()

        if self.settings.get('debug'):
            self.settings.setdefault('serve_traceback', True)
            from tornado import autoreload
            autoreload.start()

    def add_handlers(self, handlers):
        """Appends the given handlers to our handler list.

        Handlers are processed sequentially in the order they were
        added. All matching patterns will be considered.

        we add commands and help command to handlers
        """
        for _handler in handlers:
            handler = _handler[0] if isinstance(_handler, (list, tuple)) else _handler
            self._add_handler(handler, _handler)

    def _add_handler(self, handler, _handler=None):
        for command in _find_commands_in_handler(handler):
            spec = list()
            spec.insert(0, r"%s" % (command.lower(),))
            spec.insert(1, handler)
            if isinstance(_handler, (list, tuple)):
                spec.append(_handler[1:-1])

            self.handlers.append(CommandSpec(*spec))
            self.stats[command] = 0

    def register_default_handlers(self):
        self.add_handlers([(HelpCommandHandler, dict()), (CommandsCommandHandler, dict())])

    def start_request(self, server_connection, connection):
        return _RequestExecutor(self, server_connection, connection)

    def find_handler(self, command):
        # Identify the handler to use as soon as we have the command.
        for spec in self.handlers:
            if spec.name == command:
                return spec

    def increment_stat(self, command):
        if command in self.stats:
            self.stats[command] += 1


class _RequestExecutor(object):
    def __init__(self, application, server_connection, connection):
        self.server_connection = server_connection
        self.connection = connection
        self.application = application
        self.command = None
        self.handler_kwargs = None
        self.handler_class = None

    def headers_received(self, headers):
        self.connection.context.set_headers(headers)

    def command_received(self, command):
        self.set_command(Command(command=command, headers=self.connection.context.headers, connection=self.connection))

    def set_command(self, command):
        self.command = command
        self._find_handler()
        self.command.set_argument_map(self.handler_class.get_command_arguments_map(self.command.name))

    def _find_handler(self):
        spec = self.application.find_handler(self.command.name)
        if not spec:
            spec = CommandSpec(None, CommandNotFoundHandler)

        self.handler_class = spec.handler
        self.handler_kwargs = spec.kwargs

    def parameters_received(self, parameters):
        self.command.set_parameters(parameters)

    def get_command_arguments(self):
        return self.command.get_arguments_map()

    def finish(self):
        self.execute()

    def execute(self):
        handler = self.handler_class(self.application, self.command,
                                     **self.handler_kwargs)
        handler._execute()
