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

:FIXME: Fix the description below.

For Outgoing Requests
=====================

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

For Incoming Requests
=====================

-r (request-text): Sent by another client, this is the request the connector
    receives.

License
=======

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

import bjsonrpc
import json
from optparse import OptionParser
import pipes
import sys

import santiago
import subprocess

SANTIAGO_INSTANCE = BJSONRPC_SERVER = None

def interpret_args(args, parser=None):
    """Convert command-line arguments into options."""

    if parser == None:
        parser = OptionParser()

    parser.add_option("-k", "--key", dest="key",
                      help="Find services for or by this buddy.")

    parser.add_option("-c", "--consuming", dest="consuming", 
                      action="store_true",help="""\
Query the named key's FreedomBuddy service for the named service's location.

I'm consuming that service from the host.
""")
    parser.add_option("-o", "--hosting", dest="hosting", action="store_true",
                      help="""\
Query my FreedomBuddy service for locations I'm hosting the service for the
client.

I'm hosting that service for the client.
""")
    parser.add_option("-s", "--service", dest="service",
                      help="Find this service's locations.")
    parser.add_option("-l", "--location", dest="location", help="""\
The service locations to add or remove.
""")
    parser.add_option("-a", "--action", dest="action", help="""\
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

    # request actions: handle external I/O
    parser.add_option("-r", "--request", dest="request", help="""\
Handle an incoming request response.
""")
    parser.add_option("-q", "--query", dest="query", action="store_true",
                      help="""\
Create an outgoing request query.
""")

    # state actions: start or terminate FreedomBuddy.
    parser.add_option("", "--stop", dest="stop", default=None,
                      action="store_true", help="""\
Stop the connector.
""")

    return parser.parse_args(args)

def validate_args(options, parser=None):
    """Errors out if options are invalid."""

    if parser == None:
        parser = OptionParser()

    if options.request:
        pass
    elif options.stop:
        pass
    # if consuming or hosting, key is required.
    elif (options.key != None and
             (options.consuming, options.hosting) != (None, None)):
        pass
    elif  (options.consuming, options.hosting) != (None, None):
        pass
    # if query, key and service are required.
    elif None not in (options.query, options.key, options.service):
        pass
    else:
        help_me(parser)

def help_me(parser=None):
    """Help text."""

    if parser == None:
        parser = OptionParser()

    parser.error("""\
Usage Instructions:

    One of the following is required:

    --key and --service to request a new service location.
    --stop to stop this connector.
    --request to handle an incoming request.
""")


def start(santiago_to_use, *args, **kwargs):
    """The final startup step in the system.

    Create the server.

    """
    global SANTIAGO_INSTANCE, BJSONRPC_SERVER
    SANTIAGO_INSTANCE = santiago_to_use
    BJSONRPC_SERVER = bjsonrpc.createserver(host="127.0.0.1",
                                            handler_factory=BjsonRpcHost)
    BJSONRPC_SERVER.serve()
    print("served!")

def stop(santiago_to_use, *args, **kwargs):
    """Shut down the server."""

    pass


class CliListener(santiago.SantiagoListener):
    """The command line interface FBuddy Listener."""

    pass

class CliSender(santiago.SantiagoSender):
    """The command line sender for FBuddy"""
    def __init__(self, https_sender = None, cli_sender = None, *args, **kwargs):
        super(CliSender, self).__init__(*args, **kwargs)

        self.senders = {"https": https_sender, "cli": cli_sender}

    def outgoing_request(self, request, destination):
        """Send a request out through the command line interface.

        Don't queue, just immediately send the reply to each location we know.

        """
        protocol = destination.split(":")[0]

        code = self.senders[protocol]
        code = code.replace("$DESTINATION", pipes.quote(str(destination)))
        code = code.replace("$REQUEST", pipes.quote(str(request)))

        subprocess.call(code)


class BjsonRpcHost(bjsonrpc.handlers.BaseHandler):
    """

    FIXME: Separate the Monitor and Listener, this exposes the core to any
    FIXME: authentication bugs in each client.  It *should* follow the structure
    FIXME: of the HTTPS Controller module, where clients can selectively expose
    FIXME: the listener while keeping the monitor hidden.

    """
    def _setup(self):
        self.listener = load_connector("listeners")
        self.sender = load_connector("senders")
        self.querier = santiago.Query(SANTIAGO_INSTANCE)

    def incoming_request(self, *args, **kwargs):
        return self.listener.incoming_request(*args, **kwargs)

    def outgoing_request(self, *args, **kwargs):
        return self.sender.outgoing_request(*args, **kwargs)

    def query(self, *args, **kwargs):
        return self.querier.POST(*args, **kwargs)

    def stop(self):
        """Quit the server and stop Santiago."""

        BJSONRPC_SERVER.stop()
        santiago.Stop(SANTIAGO_INSTANCE).POST()

    def consuming(self, operation, host, service=None, location=None):
        """Update a service I consume from other hosts."""

        return self._change(operation, False, host, service, location)

    def hosting(self, operation, client, service=None, location=None):
        """Update a service I am hosting for other clients."""

        return self._change(operation, True, client, service, location)

    def _change(self, operation, i_host, key, service=None, location=None):
        """Change Santiago's known clients, servers, services, and locations."""

        if operation == "add":
            action = "PUT"
        elif operation == "remove":
            action = "DELETE"
        elif operation == "list":
            action = "GET"
        else:
            action = "GET"

        # if we're modifying data
        if action != "GET":
            if location != None:
                actor = santiago.HostedService if i_host else santiago.ConsumedService
            elif service != None:
                actor = santiago.HostedClient if i_host else santiago.ConsumedHost
            elif key != None:
                actor = santiago.Hosting if i_host else santiago.Consuming
            else:
                actor = None
        # just listing data, don't need to handle listing indvidiual locations.
        elif action == "GET":
            if service != None:
                actor = santiago.HostedService if i_host else santiago.ConsumedService
            elif key != None:
                actor = santiago.HostedClient if i_host else santiago.ConsumedHost
            else:
                actor = santiago.Hosting if i_host else santiago.Consuming

        # for the day that I change things up and completely forget to update
        # this line.
        else:
            raise RuntimeError("Invalid Action.")

        # think:
        #     x = santiago.ConsumedService(SANTIAGO_INSTANCE)
        #     x.GET(key, service, location)
        return json.dumps(getattr(actor(SANTIAGO_INSTANCE), action)(key,
                                                  service=service,
                                                  location=location))

def load_connector(attr):
    """Load the cli-specific connector from the Santiago Instance.

    Ignore KeyErrors, if they occur: in these cases, the user didn't want to
    use optional functionality.

    """
    try:
        return getattr(SANTIAGO_INSTANCE, attr)["cli"]
    except KeyError:
        pass


def main():

    parser = OptionParser()
    (options, args) = interpret_args(sys.argv[1:], parser)
    validate_args(options, parser)

    connect = bjsonrpc.connect()

    if options.request:
        print(connect.call.incoming_request([options.request]))
    elif options.stop:
        print(connect.call.stop())
    elif options.consuming:
        print(connect.call.consuming(options.action, options.key,
                         options.service, options.location))
    elif options.hosting:
        print(connect.call.hosting(options.action, options.key,
                       options.service, options.location))
    elif options.query:
        print(connect.call.query(host=options.key, service=options.service))
    else:
        help_me()


if __name__ == "__main__":

    main()
