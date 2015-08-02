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

import traceback
import sys
import functools
import inspect

from tornado.gen import is_future
from tornado import gen
from tornado.log import app_log, gen_log
from tornado.util import import_object
from tornado.web import Finish
from tornado.escape import utf8, unicode_type


def _find_commands_in_handler(cls):
    if not issubclass(cls, CommandHandler):
        raise TypeError("expected subclass of CommandHandler, got %r", cls)
    _commands = set()
    _parameters_map = {}
    for name in dir(cls):
        attr = getattr(cls, name)
        if inspect.ismethod(attr):
            if hasattr(attr, "_is_command"):
                _commands.add(name.lower())
                _parameters_map[name] = []
                for param in getattr(attr, "_parameters"):
                    if param is not None:
                        _parameters_map[name].insert(0, param)

    cls._SUPPORTED_COMMANDS = _commands
    cls._COMMAND_ARGUMENT_MAP = _parameters_map

    return _commands


def _create_help(command_name, param_name=None, help=None):
    if command_name not in BaseHelpHandler.CommandList:
        BaseHelpHandler.CommandList[command_name] = {"usage": [], "description": []}

    if param_name is None and help is not None:
        BaseHelpHandler.CommandList[command_name]["description"].insert(0, "%s" % (help,))
        return

    if help:
        BaseHelpHandler.CommandList[command_name]["description"].insert(0, "  %s %s" % (param_name, help))

    if param_name:
        BaseHelpHandler.CommandList[command_name]["usage"].insert(0, param_name)


def parameter(name=None, multiple=False, help=None, default=None, type=None):
    def decorator(function):
        functools.wraps(function)
        f_name = getattr(function, "_command_name", function.__name__)
        _parameters = getattr(function, "_parameters", [])
        _parameters.append({
            "name": name,
            "multiple": multiple,
            "default": default,
            "type": type
        })
        _create_help(f_name, name, help)

        def wrapped(instance, *args, **kwargs):
            return function(instance, *args, **kwargs)

        wrapped._is_command = True
        wrapped._command_name = f_name
        wrapped._parameters = _parameters
        return wrapped

    return decorator


class Command(object):
    _COMMAND_ARGUMENT_MAP = {}

    def __init__(self, command=None, connection=None, headers=None):
        self.name = command.strip()
        self.connection = connection
        self.headers = headers

    def __repr__(self):
        return "%s(%s)" % (self.name, self.headers)

    def set_argument_map(self, _map):
        self._COMMAND_ARGUMENT_MAP = _map

    def get_arguments_map(self):
        return self._COMMAND_ARGUMENT_MAP

    def finish(self):
        """Finishes this HTTP request on the open connection.

        .. deprecated:: 4.0
           Use ``request.connection`` and the `.HTTPConnection` methods
           to write the response.
        """
        self.connection.finish()


class CommandSpec(object):
    def __init__(self, name, handler, kwargs=None):
        if isinstance(handler, str):
            # import the Module and instantiate the class
            # Must be a fully qualified name (module.ClassName)
            handler = import_object(handler)

        self.handler = handler
        self.kwargs = kwargs or {}
        self.name = name


class CommandError(Exception):
    """An exception that will turn into an command error response.

    Raising an `CommandError` is a convenient alternative to calling
    `CommandHandler.send_error` since it automatically ends the
    current function.

    To customize the response sent with an `CommandError`, override
    `CommandHandler.write_error`.

    :arg string message: Message to be written to the client
    """

    def __init__(self, message=None, **kwargs):
        self.message = message or kwargs.get('message', "Unknown")

    def __str__(self):
        return self.message


class CommandHandler(object):
    _SUPPORTED_COMMANDS = {}
    _COMMAND_ARGUMENT_MAP = {}

    def __init__(self, application, command, **kwargs):
        super(CommandHandler, self).__init__()

        self.application = application
        self.command = command
        self.initialize(**kwargs)

        self._finished = False
        self._auto_finish = True
        self._transforms = None  # will be set in _execute
        self._prepared_future = None
        self._write_buffer = []
        self._status_code = 200
        self._finished = False

    def initialize(self, **kwargs):
        pass

    def prepare(self):
        pass

    @classmethod
    def get_command_arguments_map(cls, command):
        return cls._COMMAND_ARGUMENT_MAP.get(command, {})

    @property
    def settings(self):
        """An alias for `self.application.settings <Application.settings>`."""
        return self.application.settings

    @gen.coroutine
    def _execute(self):
        try:
            result = self.prepare()
            if is_future(result):
                result = yield result
            if result is not None:
                raise TypeError("Expected None, got %r" % result)
            if self._finished:
                return
            command_method = getattr(self, self.command.name.lower())
            result = command_method()
            if is_future(result):
                result = yield result
            if result is not None:
                raise TypeError("Expected None, got %r" % result)
            if self._auto_finish and not self._finished:
                self.finish()
        except Exception, e:
            try:
                self.handle_command_exception(e)
            except Exception:
                app_log.error("Exception in exception handler", exc_info=True)

    def handle_command_exception(self, e):
        if isinstance(e, Finish):
            # Not an error; just finish the request without logging.
            if not self._finished:
                self.finish()
            return
        try:
            self.log_exception(*sys.exc_info())
        except Exception:
            # An error here should still get a best-effort send_error()
            # to avoid leaking the connection.
            app_log.error("Error in exception logger", exc_info=True)
        if self._finished:
            # Extra errors after the request has been finished should
            # be logged, but there is no reason to continue to try and
            # send a response.
            return
        if isinstance(e, CommandError):
            self.send_error(e.message, exc_info=sys.exc_info())
        else:
            self.send_error("Internal Server Error", exc_info=sys.exc_info())

    def send_error(self, message=None, **kwargs):
        """Sends the given command error to the client.

        If `flush()` has already been called, it is not possible to send
        an error, so this method will simply terminate the response.
        If output has been written but not yet flushed, it will be discarded
        and replaced with the error message.

        Override `write_error()` to customize the error page that is returned.
        Additional keyword arguments are passed through to `write_error`.
        """
        self.clear()
        if 'exc_info' in kwargs:
            exception = kwargs['exc_info'][1]
            if isinstance(exception, CommandError) and exception.message:
                message = exception.message
        try:
            self.write_error(message, **kwargs)
        except Exception:
            app_log.error("Uncaught exception in write_error", exc_info=True)
        if not self._finished:
            self.finish()

    def write_error(self, message, **kwargs):
        """Override to implement custom error format.

        ``write_error`` may call `write`

        If this error was caused by an uncaught exception (including
        CommandError), an ``exc_info`` triple will be available as
        ``kwargs["exc_info"]``.  Note that this exception may not be
        the "current" exception for purposes of methods like
        ``sys.exc_info()`` or ``traceback.format_exc``.
        """
        if self.settings.get("serve_traceback") and "exc_info" in kwargs:
            for line in traceback.format_exception(*kwargs["exc_info"]):
                self.write(line)
            self.finish()
        else:
            self.finish("-ERR %s" % (message,))

    def clear(self):
        self._write_buffer = []

    def log_exception(self, typ, value, tb):
        if isinstance(value, CommandError):
            if value.message:
                format = "%s: " + value.message
                args = ([self._command_summary()] +
                        list(value.args))
                gen_log.warning(format, *args)
        else:
            app_log.error("Uncaught exception %s\n%r", self._command_summary(),
                          self.command, exc_info=(typ, value, tb))

    def finish(self, chunk=None):
        """Finishes this response, ending the command."""
        if self._finished:
            raise RuntimeError("finish() called twice")

        if chunk is not None:
            self.write(chunk)

        self.flush()
        self.command.finish()

        self._finished = True
        self.application.increment_stat(self.command.name)
        self.on_finish()

    def on_finish(self):
        """Called after the end of a request.

        Override this method to perform cleanup, logging, etc.
        This method is a counterpart to `prepare`.  ``on_finish`` may
        not produce any output, as it is called after the response
        has been sent to the client.
        """
        pass

    def flush(self, callback=None):
        """Flushes the current output buffer to the network.

        The ``callback`` argument, if given, can be used for flow control:
        it will be run when all flushed data has been written to the socket.
        Note that only one flush callback can be outstanding at a time;
        if another flush occurs before the previous flush's callback
        has been run, the previous callback will be discarded.
        """
        chunk = b"\r\n".join(self._write_buffer)
        self._write_buffer = []
        return self.command.connection.write(chunk + "\r\n", callback=callback)

    def _command_summary(self):
        return "%s %s" % (self.command.connection.context.remote_ip, self.command.name)

    def write(self, chunk):
        """Writes the given chunk to the output buffer.

        To write the output to the network, use the flush() method below.
        """
        if self._finished:
            raise RuntimeError("Cannot write() after finish()")
        if not isinstance(chunk, (bytes, unicode_type, int, float, bool)):
            raise TypeError("write() only accepts bytes,unicode, int, float, bool")
        if isinstance(chunk, (int, float, bool)):
            chunk = ("%s" % (chunk,)).lower()
        chunk = utf8(chunk)
        self._write_buffer.append(chunk)


class CommandNotFoundHandler(CommandHandler):
    def prepare(self):
        raise CommandError("Command not found (%s)" % (self.command.name.lower()))


class BaseHelpHandler(CommandHandler):
    CommandList = {}

    @staticmethod
    def get_help(command):
        usage = HelpCommandHandler.CommandList.get(command).get("usage")
        description = HelpCommandHandler.CommandList.get(command).get("description")

        response = list()
        response.append("Usage: %s %s" % (command, " ".join(usage)))
        if description is not None:
            response.append("Arguments description:")
            response.append("".join(description))
        return response


class CommandsCommandHandler(BaseHelpHandler):
    @parameter(help="Commands list")
    def commands(self):
        for command in self.CommandList.iterkeys():
            if command != "commands":
                self.write("%s %s" % (command, " ".join(self.CommandList.get(command, {"usage": []}).get("usage"))))

    @parameter(help="command stats")
    def stats(self):
        for command in self.application.stats.iterkeys():
            self.write("%s: %s" % (command.lower(), self.application.stats.get(command)))


class HelpCommandHandler(BaseHelpHandler):
    @parameter(name="command", help="command")
    def help(self):
        for line in BaseHelpHandler.get_help("help"):
            self.write(line)
