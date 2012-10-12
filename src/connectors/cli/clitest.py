#! /usr/bin/env python
# -*- mode: python; mode: auto-fill; fill-column: 80; -*-

"""Testing a few socket/pipe setups.

From an interpreter:

import sys
sys.path.append(".")
import clitest
clitest.start()

From a shell:

$ python clitest.py

Watch the interpreter for output.  You'll have to restart the interpreter each
time you want to change the test method.

"""
import socket
import pdb

import sys
sys.path.append("/home/nick/programs/freedombox/bjsonrpc")
import bjsonrpc
import os


test = 4
PIPE = "fbuddy.pipe"

if test == 2:
    import pipes
    t = pipes.Template()
    t.append("cat", "--")

def start():
    if test == 0:
        # from the documentation
        import pipes
        t=pipes.Template()
        t.append('cat', '--')
        f=t.open(PIPE, 'w')
        f.write('hello world')
        f.close()
        print(open(PIPE).read())
    elif test == 1:
        # everything together
        import pipes
        t = pipes.Template()
        t.append("cat", "--")
        with t.open(PIPE, "w") as f:
            f.write("hello world!")
        with open(PIPE) as f:
            print(f.read())
    elif test == 2:
        # divided between start and main.
        with open(PIPE) as f:
            while 1:
                x = f.read()
                if x: print (x)
    elif test == 3:
        # same as 1, but without an explicit write.
        # that's done from the commandline.
        import pipes
        t = pipes.Template()
        t.append("cat", "--")
        with open(PIPE) as f:
            while 1:
                x = f.read()
                if x: print(x)
    elif test in (4, 5):
        # learning from exmachina: bjsonrpc fun times.

        class Monitor(bjsonrpc.handlers.BaseHandler):
            pass

        def run_server():
            serv = bjsonrpc.server.Server(sock, handler_factory=Monitor)
            serv.serve()


if __name__ == "__main__":
    if test == 2:
        with t.open(PIPE, "w") as f:
            f.write("hello world!")
            f.flush()
    elif test == 4:
        class FBuddyClient(object):
            def __init__(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.bind(PIPE)
                self.conn = bjsonrpc.connection.Connection(self.sock)

            def echo(self, input):
                print(input)
                return input

            def __getattribute__(self, key):
                """Wrap calls to the connection object."""
                if not key.startswith("_"):
                    try:
                        return object.__getattr__(key, self.conn.call)
                    except AttributeError:
                        pass
                v = object.__getattribute__(self, key)
                if hasattr(v, '__get__'):
                    return v.__get__(None, self)
                return v

            def close(self):
                self.sock.close()

        try:
            os.remove(PIPE)
        except OSError:
            pass
        dog = FBuddyClient()
        dog.echo("hiya!")
        dog.sock.shutdown(socket.SHUT_RDWR)
        dog.sock.close()
        os.remove(PIPE)
    elif test == 5:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        import os
        try:
            os.mkfifo(PIPE)
        except:
            pass

        sock.connect(PIPE)
        conn = bjsonrpc.connection.Connection(sock)
        conn.call.echo("doggy!")
