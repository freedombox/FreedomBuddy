#! /usr/bin/python

"""Prints FreedomBuddy locations to screen.

This script is designed to show where a buddy is providing a service.  It
accepts a key that identifies a trusted party and the service to show locations
for.  It can show where someone else is hosting a service for me and it can show
where I am hosting a service for a client.  It will print one location per line.

:TODO: handle each of the options
"""

from optparse import OptionParser
import sys

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-k", "--key", dest="key",
                      help="Find services for or by this buddy.")
    parser.add_option("-s", "--service", dest="service",
                      help="Find this service's locations.")
    parser.add_option("-t", "--timeout", dest="timeout",
                      help="Maximum time to wait for the request to finish.")
    parser.add_option("-o", "--host", dest="host", default=True,
                      action="store_true", help="""\
Query the named key's FreedomBuddy service for the named service's location.

May not be used with --client.  If neither --host nor --client are provided,
--host is assumed.
""")
    parser.add_option("-c", "--client", dest="host", action="store_false",
                      help="""\
Query my FreedomBuddy service for locations I'm hosting the service for the
client.

May not be used with --host.
""")
    parser.add_option("-n", "--no-query", dest="query", action="store_false",
                      help="""\
Use locally cached services and don't query the host whether the between-request
timeout has expired or not.

This is implied when --client is used.  If neither --no-query or --force-query
are specified, query with normal respect for the timeout.
""")
    parser.add_option("-f", "--force-query", dest="query",
                      action="store_true", help="""\
Ignore locally cached services and query the host whether the between-request
timeout has expired or not.

This is ignored when --client is used.  If neither --no-query or --force-query
are specified, query with normal respect for the timeout.

TODO: Implement this option.
""")

    (options, args) = parser.parse_args(sys.argv[1:])
