#! /usr/bin/env python # -*- mode: auto-fill; fill-column: 80 -*-

import logging
import sys
import utilities
import ConfigParser as configparser
import santiago

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger("cherrypy.error").setLevel(logging.CRITICAL)

    config = "production.cfg"
    new_services = False
    try:
        config = sys.argv[1]
        new_services = sys.argv[2]
    except IndexError:
        pass

    # get my key, if possible
    try:
        mykey = utilities.load_config(config).get("pgpprocessor",
                                                  "keyid")
        lang = utilities.load_config(config).get("general",
                                                 "locale")
    except configparser.NoSectionError:
        mykey = 0
        lang = None

    # set up monitors, listeners, and senders
    protocol = "https"
    serving_port = 8080
    cert = "santiago.crt"

    listeners = { protocol: { "socket_port": serving_port,
                             "ssl_certificate": cert,
                             "ssl_private_key": cert
                              }, }
    senders = { protocol: { "proxy_host": "localhost",
                           "proxy_port": 8118} }
    monitors = { protocol: {} }

    # services to host and consume
    service = "freedombuddy"
    location = protocol + "://localhost"

    # go!
    if new_services:
        hosting = { mykey: { service: [location + ":" + str(serving_port)] } }
        consuming = { mykey: { service: [location + ":" + str(serving_port)] } }

        freedombuddy = santiago.Santiago(listeners, senders,
                                     hosting, consuming,
                                     me=mykey, monitors=monitors, locale=lang)
    else:
        freedombuddy = santiago.Santiago(listeners, senders,
                                     me=mykey, monitors=monitors, locale=lang)
        

    # import pdb; pdb.set_trace()
    with freedombuddy:
        pass

    santiago.debug_log("Santiago finished!")
