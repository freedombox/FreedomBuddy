#! /usr/bin/env python
# -*- mode: python; mode: auto-fill; fill-column: 80; -*-

"""Starts a test FreedomBuddy service.

Good for testing that it'll actually run and start up.  By default, it'll start
listening for connections on ``https://localhost:8080``.  It'll be hosting the
FreedomBuddy service for itself and be able to learn and provide its own
services to itself.  That will allow you to add additional services as
necessary, that you can then provide to yourself or others.

"""

import ConfigParser as configparser
import logging
from optparse import OptionParser
import sys
import utilities
import webbrowser

import santiago

def parse_args(args):
    """Interpret args passed in on the command line."""

    parser = OptionParser()

    parser.add_option("-v", "--verbose", dest="verbose", action="count",
                      help="""\
Can be given multiple times to increase logging level.  Once means show
FreedomBuddy logging messages.  Twice means show connector logging messages as
well.""")

    parser.add_option("-c", "--config", dest="config",
                      default="../data/production.cfg",
                      help="""The configuration file to use.""")

    parser.add_option("-d", "--default-services", dest="default_services",
                      action="store_true", help="""\
Whether to reset the list of hosted and consumed services to the default.""")

    parser.add_option("-f", "--forget", dest="forget_services",
                      action="store_true", help="""\
If set, don't store service data when exiting.

Useful if you want to test or experiment with new service configurations,
without overwriting your existing data.""")

    parser.add_option("-t", "--trace", dest="trace", action="store_true",
                      help="Drop into the debugger when starting FreedomBuddy.")

    return parser.parse_args(args)

def load_config(options):
    """Load data from the specified configuration file."""

    listify_string = lambda x: [item.strip() for item in x.split(",")]

    config = utilities.load_config(options.config)

    mykey = utilities.safe_load(config, "pgpprocessor", "keyid", 0)
    lang = utilities.safe_load(config, "general", "locale", "en")
    protocols = listify_string(
        utilities.safe_load(config, "connectors", "protocols"))
    connectors = {}
    force_sender = utilities.safe_load(config, "connectors", "force_sender")

    if protocols == ['']:
        raise RuntimeError("No protocols detected.  Have you run 'make'?")

    # loop through the protocols, finding connectors each protocol uses
    # load the settings for each connector.
    for protocol in protocols:
        protocol_connectors = listify_string(
            utilities.safe_load(config, protocol, "connectors"))

        if not protocol_connectors:
            continue

        for connector in protocol_connectors:
            connectors[connector] = dict(
                utilities.safe_load(config, connector, None, {}))

    return mykey, lang, protocols, connectors, force_sender

def configure_connectors(protocols, connectors):

    listeners, senders, monitors = {}, {}, {}

    for protocol in protocols:
        for connector in connectors:
            if connector == protocol + "-listener":
                listeners[protocol] = dict(connectors[protocol + "-listener"])
            elif connector == protocol + "-sender":
                senders[protocol] = dict(connectors[protocol + "-sender"])
            elif connector == protocol + "-monitor":
                monitors[protocol] = dict(connectors[protocol + "-monitor"])

    return listeners, senders, monitors

if __name__ == "__main__":

    (options, args) = parse_args(sys.argv)

    if options.trace:
        import pdb; pdb.set_trace()

    if options.verbose > 0:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("cherrypy.error").setLevel(logging.CRITICAL)
    if options.verbose > 1:
        logging.getLogger("cherrypy.error").setLevel(logging.DEBUG)

    # load configuration settings
    (mykey, lang, protocols, connectors, force_sender) = load_config(options)

    # create listeners and senders
    listeners, senders, monitors = configure_connectors(protocols, connectors)

    # services to host and consume
    url = "https://localhost:8080"

    # configure system
    # TODO Set this automatically when no relevant data/(keyid).dat file exists.
    if options.default_services:
        service = "freedombuddy"
        hosting = { mykey: { service: [url],
                             service + "-monitor" : [url + "/freedombuddy"] } }
        consuming = { mykey: { service: [url],
                             service + "-monitor" : [url + "/freedombuddy"] } }
    else:
        hosting = consuming = None

    freedombuddy = santiago.Santiago(listeners, senders, hosting, consuming,
                                     me=mykey, monitors=monitors,
                                     locale=lang, save_dir="../data",
                                     force_sender=force_sender)

    # run
    with freedombuddy:
        if "https" in protocols:
            webbrowser.open_new_tab(url + "/freedombuddy")

    santiago.debug_log("Santiago finished!")
