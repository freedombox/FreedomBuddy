#! /usr/bin/env python # -*- mode: python; mode: auto-fill; fill-column: 80; -*-

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
FreedomBuddy logging messages.  Twice means show protocol logging messages as
well.""")
    parser.add_option("-c", "--config", dest="config",
                      default="../data/production.cfg",
                      help="""The configuration file to use.""")

    parser.add_option("-d", "--default-services", dest="default_services",
                      action="store_true", help="""\
Whether to reset the list of hosted and consumed services to the default.
""")
    parser.add_option("-t", "--trace", dest="trace", action="store_true",
                      help="Drop into the debugger when starting FreedomBuddy.")

    return parser.parse_args(args)

def load_config(options):
    """Load data from the specified configuration file."""

    config = utilities.load_config(options.config)

    mykey = safe_load(config, "pgpprocessor", "keyid", 0)
    lang = safe_load(config, "general", "locale", "en")
    protocols = [safe_load(config, "connectors", "protocols", {})]
    connectors = {}

    # loop through the protocols, finding connectors each protocol uses
    # load the settings for each connector.
    for protocol in protocols:
        protocol_connectors = safe_load(config, protocol, "connectors",
            [ protocol + "-listener", protocol + "-sender",
              protocol + "-monitor" ])

        # when we do load data from the file, it's a comma-delimited string
        if hasattr(protocol_connectors, "split"):
            protocol_connectors = protocol_connectors.split(", ")

        for connector in protocol_connectors:
            connectors[connector] = dict(safe_load(config, connector, None, {}))

    return mykey, lang, protocols, connectors

def safe_load(config, section, key=None, default=None):
    """Safely load data from a configuration file."""

    try:
        if key is not None:
            return config.get(section, key)
        else:
            return config.items(section)
    except configparser.NoSectionError:
        return default


if __name__ == "__main__":

    (options, args) = parse_args(sys.argv)

    if options.verbose > 0:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("cherrypy.error").setLevel(logging.CRITICAL)
    if options.verbose > 1:
        logging.getLogger("cherrypy.error").setLevel(logging.DEBUG)

    # load configuration settings
    (mykey, lang, protocols, connectors) = load_config(options)

    listeners = {}
    senders = {}
    monitors = {}

    # create listeners and senders
    # FIXME figure out why it's incorrectly including keyid.
    for protocol in protocols:
        for connector in connectors:
            if connector.endswith("listener"):
                listeners[protocol] = dict(connectors[protocol + "-listener"])
            elif connector.endswith("sender"):
                senders[protocol] = dict(connectors[protocol + "-sender"])
            elif connector.endswith("monitor"):
                monitors[protocol] = dict(connectors[protocol + "-monitor"])

    # services to host and consume
    url = "https://localhost:8080"

    # configure system
    if options.default_services:
        service = "freedombuddy"
        hosting = { mykey: { service: [url] } }
        consuming = { mykey: { service: [url] } }

        freedombuddy = santiago.Santiago(listeners, senders, hosting, consuming,
                                         me=mykey, monitors=monitors,
                                         locale=lang, save_dir="../data")
    else:
        freedombuddy = santiago.Santiago(listeners, senders, me=mykey,
                                         monitors=monitors, locale=lang,
                                         save_dir="../data")

    # run
    if options.trace:
        import pdb; pdb.set_trace()

    with freedombuddy:
        webbrowser.open_new_tab(url + "/freedombuddy")

    santiago.debug_log("Santiago finished!")
