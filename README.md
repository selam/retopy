# retopy
tornado's web.py like tcp server

# Usage

```python
from retopy.server import RetopyServer
from retopy.server import Application
from retopy.command import CommandHandler
from retopy.command import parameter
from tornado.ioloop import IOLoop

class MyCounterHandler(CommandHandler):
    """
       Counter methods
    """
    _COUNTERS = {}

    @staticmethod
    def _check_and_create_counter(key):
        if not key in MyCommandHandler._COUNTERS:
            MyCommandHandler._COUNTERS[key] = 0

    @parameter(name="key"):
    def increment(self):
        """
        Increments the number stored at key by one. If the key does not exist,
        it is set to 0 before performing the operation.
        """
        key = self.get_argument("key")
        MyCommandHandler._check_and_create_counter(key)

        MyCommandHandler._COUNTERS[key] += 1
        self.write(MyCommandHandler._COUNTERS[key])

    @parameter(name="key")
    def decrement(self):
        """
        Decrements the number stored at key by one. If the key does not exist,
        it is set to 0 before performing the operation.
        """
        key = self.get_argument("key")
        MyCommandHandler._check_and_create_counter(key)

        MyCommandHandler._COUNTERS[key] -= 1
        self.write(MyCommandHandler._COUNTERS[key])

    @parameter("key")
    def get(self):
        """
            Get the value of key. If the key does not exist error is returned
        """
        key = self.get_argument("key")
        if not key in MyCommandHandler._COUNTERS:
            raise CommandError("%s Not found" % (key,))

        self.write(MyCommandHandler._COUNTERS.get(key))

    @parameter(name="key")
    @parameter(name="value", type=int)
    def set(self):
        """
          Set key to hold the integer value. If key already holds a value, it is overwritten.
        """
        key = self.get_argument("key")
        MyCommandHandler._check_and_create_counter(key)
        MyCommandHandler._COUNTERS[key] = self.get_argument("value")
        self.write(MyCommandHandler._COUNTERS[key])

    @parameter(name="key")
    def del(self):
        """
            Removes the specified keys. A key is ignored if it does not exist.
        """
        key = self.get_argument("key")
        try:
            del MyCommandHandler._COUNTERS[key]
        except KeyError, error:
            pass
        self.write("+OK")

    @parameter
    def ping(self):
        self.write("+PONG")

class MyPingHandler(CommandHandler):
    @parameter
    def ping(self):
        "Returns PONG. This command is often used to test if a connection is still alive, or to measure latency."
        self.write("+PONG")

class MyApplication(Application):

    def __init__(self):
        handlers = [
           (MyCommandHandler),
           (MyPingHandler)
        ]
        settings = {
            "default_handlers": True
        }
        Application.__init__(self, handlers, **settings)

s = RetopyServer(MyApplication())
s.listen(8000)
IOLoop.instance().start()
```

# Warning
it's not usable yet, you should wait couple days more