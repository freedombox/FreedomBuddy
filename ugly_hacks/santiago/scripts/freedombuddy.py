#! /usr/bin/env python # -*- mode: auto-fill; fill-column: 80 -*-

"""Prints FreedomBuddy locations to screen.

This script is designed to show where a buddy is providing a service.  It
accepts a key that identifies a trusted party and the service to show locations
for.  It can show where someone else is hosting a service for me and it can show
where I am hosting a service for a client.  It will print one location per line.

This was written to be used with a local FreedomBuddy service and it shows.
There's no way to proxy requests or send requests over anything that isn't
HTTP(S).

:TODO: allow proxies and other request methods?
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

"""

import httplib
import json
from optparse import OptionParser
import sys
import time
import urllib


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

""")
    return parser.parse_args(args)

def validate_args(options, parser=None):
    """Errors out if options are invalid."""

    if parser == None:
        parser = OptionParser()

    if options.key == None or options.service == None:
        parser.error("--key and --service must be supplied.")

def query(conn, params, options, request_type, method="GET"):
    """Query my FreedomBuddy to find hosting or consuming locations I know."""

    conn.request(method,
                 "/{0}/{1}/{2}?{3}".format(request_type, options.key,
                                       options.service, params),)

    response = conn.getresponse()

    try:
        locations = json.loads(response.read())
    except ValueError:
        locations = []

    conn.close()

    return locations

def query_remotely(conn, params, options):
    """Query the remote FreedomBuddy to learn new services, then report back."""

    query(conn, params, options, "learn", "POST")

    time.sleep(int(options.timeout))

    return query(conn, params, options, "consuming")


if __name__ == "__main__":

    parser = OptionParser()
    (options, args) = interpret_args(sys.argv[1:], parser)
    validate_args(options, parser)

    request_type = "consuming" if options.host else "hosting"
    params = urllib.urlencode({"encoding": "json"})
    conn = httplib.HTTPSConnection(options.address, options.port)

    if options.host == False or options.query == False:
        locations = query(conn, params, options, request_type)
    else:
        locations = query_remotely(conn, params, options)

    print(" ".join(locations))
