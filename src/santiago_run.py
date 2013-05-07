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
    (mykey, protocols, connectors, force_sender) = load_config(options)

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
    santiago.debug_log("Santiago!")
    freedombuddy = santiago.Santiago(listeners, senders, hosting, consuming,
                                     my_key_id=mykey, monitors=monitors,
                                     save_dir="../data",
                                     force_sender=force_sender)

    # run
    with freedombuddy:
        if "https" in protocols:
            webbrowser.open_new_tab(url + "/freedombuddy")

    santiago.debug_log("Santiago finished!")
