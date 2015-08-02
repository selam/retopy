# retopy
tornado's web.py like tcp server

# Usage

```python
#!/usr/bin/env python

from retopy.server import RetopyServer
from retopy.server import Application
from retopy.command import CommandHandler
from retopy.command import parameter, authenticated
from retopy.command import CommandError
from tornado.ioloop import IOLoop


class MyCounterHandler(CommandHandler):
    """
       Counter methods
    """
    _COUNTERS = {}

    @staticmethod
    def _check_and_create_counter(key):
        if not key in MyCounterHandler._COUNTERS:
            MyCounterHandler._COUNTERS[key] = 0

    @parameter(name="key")
    def increment(self):
        """
        Increments the number stored at key by one. If the key does not exist,
        it is set to 0 before performing the operation.
        """
        key = self.get_argument("key")
        MyCounterHandler._check_and_create_counter(key)

        MyCounterHandler._COUNTERS[key] += 1
        self.write(MyCounterHandler._COUNTERS[key])

    @parameter(name="key")
    def decrement(self):
        """
        Decrements the number stored at key by one. If the key does not exist,
        it is set to 0 before performing the operation.
        """
        key = self.get_argument("key")
        MyCounterHandler._check_and_create_counter(key)

        MyCounterHandler._COUNTERS[key] -= 1
        self.write(MyCounterHandler._COUNTERS[key])

    @parameter("key")
    def get(self):
        """
            Get the value of key. If the key does not exist error is returned
        """
        key = self.get_argument("key")
        if key not in MyCounterHandler._COUNTERS:
            raise CommandError("%s Not found" % (key,))

        self.write(MyCounterHandler._COUNTERS.get(key))

    @parameter(name="key")
    @parameter(name="value", type=int)
    def set(self):
        """
          Set key to hold the integer value. If key already holds a value, it is overwritten.
        """
        key = self.get_argument("key")
        MyCounterHandler._check_and_create_counter(key)
        MyCounterHandler._COUNTERS[key] = self.get_argument("value")
        self.write(MyCounterHandler._COUNTERS[key])

    @parameter(name="key")
    def rem(self):
        """
            Removes the specified keys. A key is ignored if it does not exist.
        """
        key = self.get_argument("key")
        try:
            del MyCounterHandler._COUNTERS[key]
        except KeyError, error:
            pass
        self.write("+OK")


class MyPingHandler(CommandHandler):
    @parameter()
    def ping(self):
        """Returns PONG. This command is often used to test if a connection is still alive, or to measure latency."""
        self.write("+PONG")


class MyLoginHandler(CommandHandler):

    @parameter()
    @authenticated
    def auth_test(self):
        self.write("authorized to run this command")

    @parameter(name="username")
    @parameter(name="password")
    def authenticate(self):
        username = self.get_argument("username")
        password = self.get_argument("password")

        if not username == u"myusername" and not password == u"mypass":
            raise CommandError("Wrong username or password")

        self.command.user = username
        self.write("+OK")


class MyApplication(Application):

    def __init__(self):
        handlers = [
            (MyCounterHandler,),
            (MyPingHandler,),
            (MyLoginHandler,)
        ]
        settings = {
            "default_handlers": True
        }
        Application.__init__(self, handlers, **settings)


s = RetopyServer(MyApplication())
s.listen(8000)
IOLoop.instance().start()
```

# client connection

When client connected to server it must send to some headers in first line
there is no any specific headers right now so just send it one character for test purposes.
headers line designed for handshake with client and server for some core features like 
gzip encoding both client and server side, authentication and such but not implemented yet, 
usage examples will be updated after handshake implementation 

after sending headers you can start sending commands,
available commands in example above:
```
test_auth 
set key value
get key
ping 
authenticate username password
increment key
rem key
decrement key
```
available commands in default handlers
```
commands
help command
stats 
```
# example usage:
right now there is no client library but it will be in feature. you can test your commands with telnet

```
timu@jarjar:~$ telnet 127.0.0.1 8000  
Trying 127.0.0.1...  
Connected to 127.0.0.1.  
Escape character is '^]'.  
header line   
increment a  
1  
increment a  
2  
increment b  
1  
increment a  
3  
rem a  
+OK  
get a  
-ERR a Not found  
``` 