#! /usr/bin/env python
# -*- mode: python; mode: auto-fill; fill-column: 80; -*-

"""Prints FreedomBuddy locations to screen.

This script is designed to show where a buddy is providing a service.  It
accepts a key that identifies a trusted party and the service to show locations
for.  It can show where someone else is hosting a service for me and it can show
where I am hosting a service for a client.  It will print one location per line.

This was written to be used with a local FreedomBuddy service and it shows.
There's no way to proxy requests or send requests over anything that isn't
HTTP(S).

:FIXME: add proxying.
:FIXME: Fix the timeout
:TODO: unit test the below:

If key or service isn't specified: quit.

If host == False: just pull the list of locations I host from the cache and
quit.

If query == False: skip querying the host and just pull the list of locations
they host for me from the cache and quit.

Until I implement active-request polling and between-request timeouts:

    query the host.

    wait the timeout.

    report the locations of the (now) locally known services and quit.

After I implement active-request polling:

    query the host.

    poll the list of active requests until the active request is handled or the
    timeout elapses.

    report the locations of the (now) locally known services and quit.

After I implement between-request timeouts:

    if (query == True) or (the timeout has elapsed and query != False): query
    the host.

    poll the list of active requests until the active request is handled or the
    timeout elapses.

    report the list of the (now) locally known services and quit.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along
with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import httplib
import json
from optparse import OptionParser
import sys
import time
import urllib

import santiago
import sys
sys.path.append("/home/nick/programs/freedombox/bjsonrpc")
import bjsonrpc


def interpret_args(args, parser=None):
    """Convert command-line arguments into options."""

    if parser == None:
        parser = OptionParser()

    parser.add_option("-k", "--key", dest="key",
                      help="Find services for or by this buddy.")
    parser.add_option("-s", "--service", dest="service",
                      help="Find this service's locations.")
    parser.add_option("-t", "--timeout", dest="timeout", default=1,
                      help="""\
Maximum time, in seconds, to wait for the request to finish.
""")
    parser.add_option("-a", "--address", dest="address", default="localhost",
                      help="""\
The "local" FreedomBuddy address to query for services.

Doesn't necessarily have to be local, just has to be reachable and trusted.
""")
    parser.add_option("-p", "--port", dest="port", default=8080,
                      help="Localhost's FreedomBuddy port.")
    parser.add_option("-o", "--host", dest="host", default=True,
                      action="store_true", help="""\
Query the named key's FreedomBuddy service for the named service's location.

If neither --host nor --client are provided, --host is assumed.  If both are
supplied, the last one wins.
""")
    parser.add_option("-c", "--client", dest="host", action="store_false",
                      help="""\
Query my FreedomBuddy service for locations I'm hosting the service for the
client.

Overridden by --host.  If neither --host nor --client are provided, --host is
assumed.  If both are supplied, the last one wins.
""")
    parser.add_option("-n", "--no-query", dest="query", action="store_false",
                      help="""\
Use locally cached services and don't query the host whether the between-request
timeout has expired or not.

Implied when --client is used.  If neither --no-query or --force-query are
specified, query with normal respect for the timeout.  If both are supplied, the
last one wins.
""")
    parser.add_option("-f", "--force-query", dest="query",
                      action="store_true", help="""\
Ignore locally cached services and query the host whether the between-request
timeout has expired or not.

Ignored when --client is used.  If neither --no-query or --force-query are
specified, query with normal respect for the timeout.  If both are supplied, the
last one wins.

TODO: Implement this option.
""")
    parser.add_option("-i", "--action", dest="action", default="",
                      help="""\
Sends commands directly to the FreedomBuddy system.

This option is meant to be used by utilities that need direct access to the
data, it is not meant to and should not be used by users.

Must be one of:

- GET: Retrieve data from the service.
- POST: Set data in the service.
- PUT: Add a new element.
- DELETE: Delete the listed item.

If this option is specified, you must also specify the rest of the
connection arguments.

""")
    return parser.parse_args(args)

def validate_args(options, parser=None):
    """Errors out if options are invalid."""

    if parser == None:
        parser = OptionParser()

    if options.key == None or options.service == None:
        parser.error("--key and --service must be supplied.")


class Monitor(santiago.SantiagoMonitor, bjsonrpc.handlers.BaseHandler):
    """The command line interface FBuddy monitor.

    FIXME: look into asyncore_ and asynchat_.  bjsonrpc blocks.

    I need something that has non-blocking IO.  I don't care if the request is
    synchronous or not (this client should wait), but we can't block the
    Santiago server while waiting for input (as then we could only have a single
    listener).  I might just need to master threading as well.

    .. _asyncore: http://docs.python.org/library/asyncore.html
    .. _asynchat: http://docs.python.org/library/asynchat.html

    """
    def __init__(self, *args, **kwargs):
        santiago.debug_log("Initializing CLI Monitor.")

        super(Monitor, self).__init__(*args, **kwargs)

    def echo(self, data):
        return data


def start(*args, **kwargs):
    """The final startup step in the system.

    Create the server.

    """
    s = bjsonrpc.createserver(host="0.0.0.0", handler_factory=Monitor)
    s.serve()
    print("served!")

def stop(*args, **kwargs):
    """Shut down the server."""

    pass


def query_remotely(address, port, key, service, params=None, timeout=1):
    """Query the remote FreedomBuddy to learn new services, then report back.

    :conn: The HTTP(S) connection to send the request along.  Requires
    ``conn.request`` and ``conn.get_response``.

    :key: The other FreedomBuddy service to query.

    :service: The particular data to ask the other FBuddy for.

    For example, if I wanted to ask Dave (who's key was "0x3") for his
    "wikipedia" service (he makes parody articles, he's a funny guy), I'd have
    to ask my FreedomBuddy service to find him:

    query_remotely(
        "localhost", 8080, # my FreedomBuddy service
        0x3,         # will ask Dave's FreedomBuddy service
        "wikipedia") # for the address of his wikipedia service

    Neat, huh?

    """
    # FIXME use socket, not http, especially since it doesn't validate certs.
    conn = httplib.HTTPSConnection(address, port)
    query(conn, "learn", key, service, "POST")
    conn.close()

    time.sleep(timeout)

    # FIXME use socket, not http, especially since it doesn't validate certs.
    conn = httplib.HTTPSConnection(address, port)
    locations = query(conn, "consuming", key, service, params=params)
    conn.close()

    return locations

def query(*args, **kwargs):
    """Unwrap controller's json."""

    try:
        return httpcontroller.query(*args, **kwargs)
    except (ValueError, TypeError):
        pass

if __name__ == "__main__":

    # self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # self.sock.connect(PIPE)
    # self.conn = bjsonrpc.connection.Connection(self.sock)

    c = bjsonrpc.connect()
    print c.call.echo("whee!")

    # parser = OptionParser()
    # (options, args) = interpret_args(sys.argv[1:], parser)
    # validate_args(options, parser)

    # type = "consuming" if options.host else "hosting"
    # # FIXME replace with socket communications.
    # conn = httplib.HTTPSConnection(options.address, options.port)
    # params={"encoding": "json"}

    # if not options.action:
    #     options.action = "GET"

    # if options.host == False or options.query == False:
    #     response = query(conn, type, options.key,
    #                      options.service, options.action, params=params)
    # else:
    #     response = query_remotely(options.address, options.port, options.key,
    #                               options.service, params=params)

    # conn.close()

    # if response:
    #     print(response)
