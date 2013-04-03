"""Shared utilities.

Currently contains a bunch of errors and config-file shortcuts.

"""

import ConfigParser as configparser
import gnupg
from optparse import OptionParser

def load_config(configfile="../data/test.cfg"):
    """Returns data from the named config file."""

    config = configparser.ConfigParser()
    config.read([configfile])
    return config

def get_config_values(config):
    """Load data from the specified configuration file."""

    listify_string = lambda x: [item.strip() for item in x.split(",")]

    mykey = safe_load(config, "pgpprocessor", "keyid", 0)
    protocols = listify_string(
        safe_load(config, "connectors", "protocols"))
    connectors = {}
    force_sender = safe_load(config, "connectors", "force_sender")

    if protocols == ['']:
        raise RuntimeError("No protocols detected.  Have you run 'make'?")

    # loop through the protocols, finding connectors each protocol uses
    # load the settings for each connector.
    for protocol in protocols:
        protocol_connectors = listify_string(
            safe_load(config, protocol, "connectors"))

        if not protocol_connectors:
            continue

        for connector in protocol_connectors:
            connectors[connector] = dict(
                safe_load(config, connector, None, {}))

    return mykey, protocols, connectors, force_sender

def configure_connectors(protocols, connectors):
    """Create listeners/senders/monitors from procotols & connectors"""
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

def multi_sign(message="hi", iterations=3, keyid=None, gpg=None):
    """Sign a message several times with a specified key."""

    messages = [message]

    if not gpg:
        gpg = gnupg.GPG(use_agent = True)
    if not keyid:
        keyid = load_config("data/test.cfg").get("pgpprocessor", "keyid")

    for i in range(iterations):
        messages.append(str(gpg.sign(messages[i], keyid=keyid)))

    return messages

def safe_load(config, section, key=None, default=None):
    """Safely load data from a configuration file."""

    try:
        if key is not None:
            return config.get(section, key)
        else:
            return config.items(section)
    except (configparser.NoSectionError, configparser.NoOptionError):
        return default

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

class SignatureError(Exception):
    """Base class for signature-related errors."""

    pass

class InvalidSignatureError(SignatureError):
    """The signature in this message is cryptographically invalid."""

    pass

class UnwillingHostError(SignatureError):
    """The current process isn't willing to host a service for the client."""

    pass
