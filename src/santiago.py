#! /usr/bin/env python
# -*- mode: python; mode: auto-fill; fill-column: 80; -*-

"""The FreedomBuddy (FBuddy) service.

Santiago is designed to let users negotiate services without third party
interference.  By sending OpenPGP signed and encrypted messages over HTTPS (or
other connectors) between parties, I hope to reduce or even prevent MITM
attacks.  Santiago can also use the Tor network as a proxy (with Python 2.7 or
later), allowing this negotiation to happen very quietly.

The first Santiago service queries another's index with a request.  That request
is handled and a request is returned.  Then, the reply is handled.  The upshot
is that we learn a new set of locations for the service.

:TODO: add doctests
:FIXME: allow multiple listeners and senders per connector (with different
    proxies)

This dead-drop approach is what came of my trying to learn from bug 4185.

This file is distributed under the GNU Affero General Public License, Version 3
or later.  A copy of GPLv3 is available [from the Free Software Foundation]
<https://www.gnu.org/licenses/agpl.html>.

"""

import ast
from collections import defaultdict as DefaultDict
import gnupg
import inspect
import json
import logging
import os
import shelve
import sys
import time
import urlparse

import src.pgpprocessor as pgpprocessor
from pprint import pprint
from datetime import datetime
import src.utilities as utilities

global DEBUG
DEBUG = 0


def debug_log(message):
    """Helper function for logging messages"""

    frame = inspect.stack()
    trace = inspect.getframeinfo(frame[1][0])
    location = "{0}.{1}.{2}".format(trace.filename, trace.function,
                                    trace.lineno)
    try:
        logging.debug("{0}:{1}: {2}".format(location, time.time(), message))
    finally:
        del frame, trace, location

class Santiago(object):
    """This Santiago is a less extensible Santiago.

    The client and server are unified.

    See `data model`_ for details on the REQUEST_VERSION and REPLY_VERSIONS.

    .. _data model: ../wiki/data-model.html

    """
    REQUEST_VERSION = 2
    SUPPORTED_REPLY_VERSIONS = [REQUEST_VERSION]
    # all keys must be present in the message.
    ALL_KEYS = set(("host", "client", "service", "locations", "reply_to",
                    "request_version", "reply_versions", "update"))
    # required keys may not be null
    REQUIRED_KEYS = set(("client", "host", "service",
                         "request_version", "reply_versions", "update"))
    # optional keys may be null.
    OPTIONAL_KEYS = ALL_KEYS ^ REQUIRED_KEYS
    LIST_KEYS = set(("reply_to", "locations", "reply_versions"))
    CONTROLLER_MODULE = "src.connectors.{0}.controller"

    SERVICE_NAME = "freedombuddy"


    def __init__(self, listeners=None, senders=None,
                 hosting=None, consuming=None, monitors=None,
                 my_key_id=0, reply_service=None,
                 save_dir=".", save_services=True,
                 gpg=None, force_sender=None, *args, **kwargs):

        """Create a Santiago with the specified parameters.

        listeners and senders are both connector-specific dictionaries containing
        relevant settings per connector:

            { "http": { "port": 80 } }

        hosting and consuming are service dictionaries, one being an inversion
        of the other.  hosting contains services you host, while consuming lists
        services you use, as a client.

            hosting: { "someKey": { "someService": ( "http://a.list",
                                                     "http://of.locations" )}}

            consuming: { "someKey": { "someService": ( "http://a.list",
                                                       "http://of.locations" )}}

        Messages are delivered by defining both the source and destination
        ("from" and "to", respectively).  Separating this from the hosting and
        consuming allows users to safely proxy requests for one another, if some
        hosts are unreachable from some points.

        :my_key_id: my PGP key ID.

        :reply_service: Messages between clients contain lists of keys, one of
          which is the "reply to" location.  This parameter names the key to
          check for reply locations in messages.  This is usually
          "freedombuddy".

        :save_dir: The directory to save service data to, for storage between
          sessions.

        :save_services: Whether to save service data between sessions at all.
          Technically, it's "whether service data is overwritten at the end of
          the session", but that's mostly semantics.

        """
        super(Santiago, self).__init__(*args, **kwargs)

        self.live = 1
        self.requests = DefaultDict(set)
        self.my_key_id = my_key_id
        self.gpg = gpg or gnupg.GPG(use_agent = True)
        self.connectors = set()
        self.reply_service = reply_service or Santiago.SERVICE_NAME
        self.save_services = save_services
        self.force_sender = force_sender #if force_sender in senders else None

        self.listeners = self.create_connectors(listeners, "Listener")
        self.senders = self.create_connectors(senders, "Sender")
        self.monitors = self.create_connectors(monitors, "Monitor")
        if not os.path.isdir(save_dir):
            os.makedirs(save_dir)
        self.shelf = shelve.open(save_dir.rstrip(os.sep) + os.sep +
                                 str(self.my_key_id) + ".dat")
        self.hosting = hosting if hosting else self.load_data("hosting")
        self.consuming = consuming if consuming else self.load_data("consuming")

    def create_connectors(self, data, connector_type):
        if data == None:
            return
        connectors = self._create_connectors(data, connector_type)
        self.connectors |= set(connectors.keys())

        return connectors

    def _create_connectors(self, settings, connector):
        """Iterates through each connector given, creating connectors for all.

        This assumes that the caller correctly passes parameters for each
        connector.  If not, we log a TypeError and continue to serve any
        connectors we can create successfully.  If other types of errors occur,
        we quit.

        """
        connectors = dict()

        for protocol in settings.iterkeys():
            module = Santiago._get_connector_module(protocol)
            protocol_connector = protocol.capitalize() + connector

            try:
                # use the module's connector as the protocol's connector:
                #
                # connectors["https"] = connectors.https.controller.HttpsSender(
                #         santiago=self, **settings["https"])
                connectors[protocol] = getattr(
                    module, protocol_connector)(
                        santiago_to_use = self, **settings[protocol])

            # log a type error, assume all others are fatal.
            except TypeError:
                logging.error("Could not create %s %s with %s",
                              protocol, protocol_connector,
                              str(settings[protocol]))
            except AttributeError:
                logging.debug("No %s.%s", protocol, protocol_connector)

        return connectors

    @classmethod
    def _get_connector_module(cls, connector):
        """Return the requested connector module.

        It assumes the Santiago directory is in sys.path, which seems to be a
        fair assumption.

        """
        import_name = cls.CONTROLLER_MODULE.format(connector)

        if not import_name in sys.modules:
            __import__(import_name)

        return sys.modules[import_name]

    def __enter__(self):
        """Start all listeners and senders attached to this Santiago.

        When this has finished, the Santiago will be ready to go.

        """
        self.change_state("start")

    def __exit__(self, exc_type, exc_value, traceback):
        """Clean up and save all data to shut down the service."""

        try:
            while self.live:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

        self.change_state("stop")

        if self.save_services:
            self.save_data("hosting")
            self.save_data("consuming")

        debug_log([key for key in self.shelf])

        self.shelf.close()

    def change_state(self, state):
        """Start or stop listeners and senders."""

        print("Santiago: {0}".format(state))
        debug_log("Connectors: {0}".format(state))

        l_and_s = list()

        for connectors in (self.listeners, self.senders):
            try:
                l_and_s += list(connectors.itervalues())
            except AttributeError:
                pass

        for connector in (l_and_s):
            getattr(connector, state)()

        for connector in self.connectors:
            getattr(sys.modules[Santiago.CONTROLLER_MODULE.format(connector)], 
			state)(santiago_to_use=self)

        debug_log("Santiago: {0}".format(state))

    def load_data(self, key):
        """Load hosting or consuming data from the shelf.

        To do this correctly, we need to convert the list values to sets.
        However, that can be done only after unwrapping the signed data.

        pre::

            key in ("hosting", "consuming")

        post::

            getattr(self, key) # exists

        """
        debug_log("loading data.")

        if not key in ("hosting", "consuming"):
            debug_log("bad key {0}".format(key))
            return

        message = ""

        try:
            data = self.shelf[key]
        except KeyError as error:
            logging.exception(error)
            data = dict()
        else:
            for message in pgpprocessor.Unwrapper(data, gpg=self.gpg):
                # iterations end when unwrapping complete.
                pass

            try:
                # Per Python's documentation, this is safe enough:
                # http://docs.python.org/2/library/ast.html#ast.literal_eval
                data = ast.literal_eval(str(message))
            except (ValueError, SyntaxError) as error:
                logging.exception(error)
                data = dict()

        debug_log("found {0}: {1}".format(key, data))

        return data

    def save_data(self, key):
        """Save hosting and consuming data to file.

        To do this safely, we'll need to convert the set subnodes to lists.
        That way, we'll be able to sign the data correctly.

        pre::

            key in ("hosting", "consuming")

        """
        debug_log("saving data.")

        if not key in ("hosting", "consuming"):
            debug_log("bad key {0}".format(key))
            return

        data = getattr(self, key)

        data = str(self.gpg.encrypt(str(data), (str(self.my_key_id)),
                                    default_key=self.my_key_id))

        self.shelf[key] = data

        debug_log("saved {0}: {1}".format(key, data))


    def i_am(self, server):
        """Verify whether this server is the specified server."""

        return self.my_key_id == server

    @classmethod
    def update_time(cls, service):
        """Return the update time key for the service.

        This pseudo-service name represents when the service was last updated.

        """
        return str(service) + "-update-timestamp"

    def valid_hosting_update(self, client, service, update):
        """Is the client's update time valid?

        A valid update time has two critieria:

        - It is newer than previous update times.
        - It is not from the future.

        See Santiago.valid_update_time for more detail.

        """
        return self.valid_update_time(True, client, service, update)

    def valid_consuming_update(self, host, service, update):
        """Is the host's update time valid?
        A valid update time has two critieria:

        - It is newer than previous update times.
        - It is not from the future.

        See Santiago.valid_update_time for more detail.

        """
        return self.valid_update_time(False, host, service, update)

    def valid_update_time(self, hosting, peer, service, update):
        """Is the peer's update time valid?

        A valid update time has two critieria:

        - It is newer than previous update times.
        - It is not from the future.

        The following snippets exercise these behaviors:

        >>> import time
        >>> hosting = True, peer = 0, service = 0, update = time.time()
        >>> set_hosting_time = lambda x: self.hosting[peer][Santiago.update_time(service)] = x
        >>> set_consuming_time = lambda x: self.consuming[peer][Santiago.update_time(service)] = x

        - Newer update times succeed::

        >>> set_hosting_time(1)
        >>> self.valid_update_time(hosting, peer, service, update)
        True

        - Older update times fail::

        >>> set_consuming_time(update - 1)
        >>> self.valid_update_time(!hosting, peer, service, update)
        False

        - Future update times fail::

        >>> set_hosting_time(update - 1)
        >>> self.valid_update_time(hosting, peer, service, time.time() + 1)
        False

        The update time must be a valid Python time (of the sort produced by
        time.time()).

        pre::

            update == float(update) # update can be a float.

        """
        # not protected, as this must fail hard: no recovery makes sense.
        peer_list = getattr(self, { True: "hosting",
                                    False: "consuming", }[hosting])

        try:
            previous_update = peer_list[peer][Santiago.update_time(service)]
        except KeyError:
             # this is a new host or service
            previous_update = 0
        update = float(update)
        valid = (update <= time.time()) and (update > previous_update)

        if not valid:
            debug_log(
                "{0}.{1}: invalid update time: {2} vs {3} (now is {4})".format(
                    peer, service, update, previous_update, time.time()))

        return valid


    def create_hosting_client(self, client):
        """Create a hosting client if one doesn't currently exist."""

        if client not in self.hosting:
            self.hosting[client] = dict()

    def create_hosting_service(self, client, service, update):
        """Create a hosting service if one doesn't currently exist.

        Check that hosting client exists before trying to add service.

        """
        self.create_hosting_client(client)

        if not self.valid_hosting_update(client, service, update):
            return False

        if service not in self.hosting[client]:
            self.hosting[client][service] = list()

        self.hosting[client][Santiago.update_time(service)] = update

        return True


        if service not in self.hosting[client]:
            self.hosting[client][service] = list()
        if str(service)+'-update-timestamp' not in list_to_use[client]:
                list_to_use[client][str(service)+'-update-timestamp'] = None

    def create_hosting_location(self, client, service, locations, update):
        """Create a hosting service if one doesn't currently exist.

        Check that hosting client exists before trying to add service.
        Check that hosting service exists before trying to add location.

        """
        if not self.create_hosting_service(client, service, update):
            return False

        for location in locations:
            if location not in self.hosting[client][service]:
                self.hosting[client][service].append(location)

        return True

    def create_consuming_host(self, host):
        """Create a consuming host if one doesn't currently exist."""

        if host not in self.consuming:
            self.consuming[host] = dict()

    def create_consuming_service(self, host, service, update):
        """Create a consuming service if one doesn't currently exist.

        Check that consuming host exists before trying to add service.

        """
        self.create_consuming_host(host)

        if not self.valid_consuming_update(host, service, update):
            return False

        if service not in self.consuming[host]:
            self.consuming[host][service] = list()

        self.consuming[host][Santiago.update_time(service)] = update

        return True

    def create_consuming_location(self, host, service, locations, update):
        """Create a consuming location if one doesn't currently exist.

        Check that consuming host exists before trying to add service.
        Check that consuming service exists before trying to add location.

        """
        if (isinstance(service, basestring)) and (service.endswith('-update-timestamp')):
            return False
        
        if not self.create_consuming_service(host, service, update):
            return False
        self.consuming[host][service] = list()
        for location in locations:
            if location not in self.consuming[host][service]:
                self.consuming[host][service].append(location)

        return True


    def remove_hosting_client(self, client):
        """Delete client."""

        if client in self.hosting:
            del self.hosting[client]

    def remove_hosting_service(self, client, service):
        """Delete service from client."""

        if service in self.hosting[client]:
            del self.hosting[client][service]
        if Santiago.update_time(service) in self.hosting[client]:
            del self.hosting[client][Santiago.update_time(service)]

    def remove_hosting_location(self, client, service, location):
        """Delete location from client's service."""

        try:
            self.hosting[client][service].remove(location)
        except KeyError as error:
            logging.exception(error)
        except ValueError as error:
            logging.exception(error)

    def remove_consuming_host(self, host):
        """Delete host."""

        if host in self.consuming:
            del self.consuming[host]

    def remove_consuming_service(self, host, service):
        """Delete service from host."""

        if service in self.consuming[host]:
            del self.consuming[host][service]
        if Santiago.update_time(service) in self.consuming[host]:
            del self.consuming[host][Santiago.update_time(service)]

    def remove_consuming_location(self, host, service, location):
        """Delete location from host's service."""

        try:
            self.consuming[host][service].remove(location)
        except KeyError as error:
            logging.exception(error)
        except ValueError as error:
            logging.exception(error)


    def replace_consuming_location(self, host, service, locations, update):
        """Replace existing consuming locations with the new ones.

        Only services whose timestamps are newer than the previous request are
        processed.

        pre::

            update == float(update) # update is a float.

        """
        if not self.valid_consuming_update(host, service, update):
            return

        try:
            del self.consuming[host][service]
        except:
            pass

        try:
             del self.consuming[host][Santiago.update_time(service)]
        except:
            pass


        self.create_consuming_location(host, service, locations, update)

    def get_host_locations(self, client, service):
        """Return client hosting data.

        - Where I'm hosting the service for the client, or
        - What I'm hosting for the client.

        Return nothing if the client or service are unrecognized.

        """
        if client and service:
            try:
                return self.hosting[client][service]
            except KeyError as e:
                logging.exception(e)
        elif client:
            try:
                return self.hosting[client]
            except KeyError as e:
                logging.exception(e)

    def get_host_services(self, client):
        """Return what I'm hosting for the client.

        Return nothing if the client or service are unrecognized.

        """
        try:
            return self.hosting[client]
        except KeyError as error:
            logging.exception(error)

    def get_client_locations(self, host, service):
        """Return hosting data for me, the client.

        - Where the host serves the service for me, or
        - What services the host serves for me.

        """
        if service:
            try:
                return self.consuming[host][service]
            except KeyError as e:
                logging.exception(e)
        elif host:
            try:
                return self.consuming[host]
            except KeyError as e:
                logging.exception(e)

    def get_client_services(self, host):
        """Return what services the host serves for me, the client."""

        try:
            return self.consuming[host]
        except KeyError as error:
            logging.exception(error)

    def get_served_clients(self, service):
        """Return what clients I'm hosting the service for."""

        return [client for client in self.hosting if service in
                   self.hosting[client]]

    def get_serving_hosts(self, service):
        """Return which hosts are hosting the service for me."""

        return [host for host in self.consuming if service in
                   self.consuming[host]]


    def query(self, host, service):
        """Request a service from another Santiago.

        This tag starts the entire Santiago request process.

        """
        try:
            self.outgoing_request(
                host, self.my_key_id, service, None, self.consuming[host][self.reply_service])
        except Exception:
            logging.exception("Couldn't handle %s.%s", host, service)

    def outgoing_request(self, from_, to, host, client,
                         service, locations="", reply_to=""):
        """Send a request to another Santiago service.

        This tag is used when sending queries or replies to other Santiagi.

        Each incoming item must be a single item or a list.

        The outgoing ``request`` is literally the request's text.  It needs to
        be wrapped for transport across the connector.

        All outgoing requests can (and probably should) be forced through the
        client connector.

        """
        self.enqueue_request(host, service)

        request = self.pack_request(host, client, service, locations, reply_to)

        for destination in self.consuming[host][self.reply_service]:
            if self.force_sender:
                self.senders[self.force_sender].outgoing_request(request,
                                                                 destination)
            else:
                out = urlparse.urlparse(destination)
                self.senders[out.scheme].outgoing_request(request, destination)

    def pack_request(self, host, client, service, locations, reply_to):
        """Pack up a request for transport.

        :host: The host's PGP key.

        :client: The client's PGP key.

        :service: The service's name.

        :locations: a ``list`` of places the *client* can consume the *service*.

        :reply_to: a ``list`` of places the *client* should send future requests
            to.

        :update: The time the request was sent.

        """
        return self.gpg.encrypt(json.dumps(
                { "host": host, "client": client,
                  "service": service, "locations": list(locations or ""),
                  "reply_to": list(reply_to),
                  "request_version": Santiago.REQUEST_VERSION,
                  "reply_versions": list(Santiago.SUPPORTED_REPLY_VERSIONS),
                  "update": time.time(),}),
            (str(host)), default_key=self.my_key_id)

    def incoming_request(self, requests):
        """Provide a service to a client.

        This tag doesn't do any real processing, it just catches and hides
        errors from the sender, so that every request is met with silence.

        The only data an attacker should be able to pull from a client is:

        - The fact that a server exists and is serving HTTP 200s.
        - The round-trip time for that response.
        - Whether the server is up or down.

        Worst case scenario, a client causes the Python interpreter to segfault
        and the Santiago process comes down, while the system is set up to
        reject connections by default.  Then, the attacker knows that the last
        request brought down this system.

        """
        # all the logic of this function is inside a try block so that
        # no matter what happens, the sender will never hear about it.
        try:
            if(not isinstance(requests, list)):
                requests = [requests]

            for request in requests:
                debug_log("request: {0}".format(str(request)))

                unpacked = self.unpack_request(request)

                if not unpacked:
                    debug_log("opaque request.")
                else:
                    debug_log("unpacked {0}".format(str(unpacked)))

                    if unpacked["locations"]:
                        debug_log("handling reply")

                        self.handle_reply(
                            unpacked["from"], unpacked["to"],
                            unpacked["host"], unpacked["client"],
                            unpacked["service"], unpacked["locations"],
                            unpacked["reply_to"],
                            unpacked["request_version"],
                            unpacked["reply_versions"],
                            unpacked["update"])
                    else:
                        debug_log("handling request")

                        self.handle_request(
                            unpacked["from"], unpacked["to"],
                            unpacked["host"], unpacked["client"],
                            unpacked["service"], unpacked["reply_to"],
                            unpacked["request_version"],
                            unpacked["reply_versions"],
                            unpacked["update"])

        except Exception as error:
            logging.exception(error)

    def unpack_request(self, request):
        """Decrypt and verify the request.

        The request comes in encrypted and it's decrypted here.  If I can't
        decrypt it, it's not for me.  If it has no signature, I don't want it.

        Some lists are changed to sets here.  This allows for set-operations
        (union, intersection, etc) later, making things much more intuitive.

        The request and client must be of and support connector versions I
        understand.

        """
        request = self.gpg.decrypt(request)

        # skip badly signed messages or ones for other folks.
        if not (str(request) and request.fingerprint):
            debug_log("fail request {0}".format(str(request)))
            debug_log("fail fingerprint {0}".format(str(request.fingerprint)))
            return

        # copy out all white-listed keys from request, throwing away cruft
        request_body = dict()
        source = json.loads(str(request))
        try:
            key = None
            for key in Santiago.ALL_KEYS:
                request_body[key] = source[key]
        except KeyError:
            debug_log("missing key {0}".format(str(source)))
            return

        # required keys are non-null
        if None in [request_body[x] for x in Santiago.REQUIRED_KEYS]:
            debug_log("blank key {0}: {1}".format(key, str(request_body)))
            return

        if False in [type(request_body[key]) == list for key in
                     Santiago.LIST_KEYS if request_body[key] is not None]:
            return

        # versions must overlap.
        if not (set(Santiago.SUPPORTED_REPLY_VERSIONS) &
                set(request_body["reply_versions"])):
            return
        if not (set([Santiago.REQUEST_VERSION]) &
              set([request_body["request_version"]])):
            return

        # set implied keys
        request_body["from"] = request.fingerprint
        request_body["to"] = self.my_key_id

        return request_body

    def handle_request(self, from_, to_, host, client,
                       service, reply_to,
                       request_version, reply_versions, update):
        """Actually do the request processing.

        - Verify we're willing to host for both the client and proxy.  If we
          aren't, quit and return nothing.
        - Forward the request if it's not for me.
        - Learn new Santiagi if they were sent.
        - Reply to the client on the appropriate connector.

        """
        # give up if we don't host this service for the sender.
        try:
            self.hosting[from_][self.reply_service]
        except KeyError:
            debug_log("no {0} hosting for {1}".format(self.reply_service,
                                                      from_))
            return

        # give up if we won't host the service for the client.
        try:
            self.hosting[client][service]
        except KeyError:
            debug_log("no host for {0} in {1}".format(client, self.hosting))
            return

        # if we don't proxy, learn new reply locations and send the reply.
        if not self.i_am(host):
            self.proxy([to_, host, client, service, reply_to, update])
        else:
            if reply_to:
                self.replace_consuming_location(client,
                                                self.reply_service,
                                                reply_to, update)
            self.outgoing_request(
                self.my_key_id, client, self.my_key_id, client,
                service, self.hosting[client][service],
                self.hosting[client][self.reply_service])

    def proxy(self, request):
        """Pass off a request to another Santiago.

        Attempt to contact the other Santiago and ask it to reply both to the
        original host as well as me.

        """
        raise RuntimeError("Proxying is not implemented.")

    # FIXME: Need to create tests for this
    def handle_reply(self, from_, to_, host, client,
                     service, locations, reply_to,
                     request_version, reply_versions, update):
        """Process a reply from a Santiago service.

        The last call in the chain that makes up the Santiago system, we now
        take the reply from the other Santiago server and learn any new service
        locations, if we've requested locations for that service.

        """
        debug_log("local {0}".format(str(locals())))

        # give up if we won't consume the service from the proxy or the client.
        try:
            if service not in self.requests[host]:
                debug_log("unrequested service {0}: ".format(
                        service, self.requests))
                return
        except KeyError:
            debug_log("unrequested host {0}: ".format(host, self.requests))
            return

        # give up or proxy if the message isn't for me.
        if not self.i_am(to_):
            debug_log("not to {0}".format(to_))
            return
        if not self.i_am(client):
            debug_log("not client {0}".format(client))
            self.proxy()
            return

        # if we have reply locations, update those locations.
        if reply_to:
            self.replace_consuming_location(host, self.reply_service, reply_to,
                                            update)

        # if we successfully handled the request, dequeue it.
        if self.create_consuming_location(host, service, locations, update):
            self.dequeue_request(host, service)
            debug_log("Success!")
        else:
            debug_log("Failure!")

        debug_log("consuming {0}".format(self.consuming))
        debug_log("requests {0}".format(self.requests))


    def enqueue_request(self, host, service):
        """Add a request to the outstanding request queue."""

        if host not in self.requests:
            self.requests[host] = set()

        self.requests[host].add(service)

    def dequeue_request(self, host, service):
        """Remove a request from the outstanding request queue."""

        self.requests[host].remove(service)

        # clean buffers as a privacy protection.
        if not self.requests[host]:
            del self.requests[host]


class SantiagoConnector(object):
    """Generic Santiago connector superclass.

    All types of connectors should inherit from this class.  These are the
    "controllers" in the MVC paradigm.

    """
    def __init__(self, santiago_to_use = None, *args, **kwargs):
        super(SantiagoConnector, self).__init__()
        self.santiago = santiago_to_use

    def start(self, *args, **kwargs):
        """Starts the connector, called when initialization is complete.

        Cannot block.

        """
        pass

    def stop(self, *args, **kwargs):
        """Shuts down the connector.

        Cannot block.

        """
        pass

class SantiagoListener(SantiagoConnector):
    """Generic Santiago Listener superclass.

    This class contains one optional method, the request receiving method.  This
    method passes the request along to the Santiago host.

    It might be strange to provide only this particular function, but this
    allows us to separate the FreedomBuddy listener or sender from the local
    monitor, meaning that it's possible to listen on any inerface without
    anything but other FreedomBuddy hosts being able to connect over that
    interface.

    """
    def incoming_request(self, request):
        self.santiago.incoming_request(request)

class SantiagoSender(SantiagoConnector):
    """Generic Santiago Sender superclass.

    This class contains one required method, the request sending method.  This
    method sends a Santiago request via that connector.

    """
    def outgoing_request(self):
        raise Exception(
            "santiago.SantiagoSender.outgoing_request not implemented.")

class RestController(object):
    """A generic controller that reacts to the basic verbs."""

    def put(self, *args, **kwargs):
        pass

    def get(self, *args, **kwargs):
        pass

    def post(self, *args, **kwargs):
        pass

    def delete(self, *args, **kwargs):
        pass

class SantiagoMonitor(RestController, SantiagoConnector):
    """A REST controller, with a Santiago, that can be started and stopped."""

    pass


class Stop(SantiagoMonitor):
    """Stop the service."""

    def post(self, *args, **kwargs):
        self.santiago.live = 0

class Query(SantiagoMonitor):
    """A local-only interface to start the outgoing request process.

    This service request is eventually sent out to the host.

    """
    def post(self, host, service, *args, **kwargs):
        super(Query, self).post(host, service, *args, **kwargs)

        self.santiago.query(host, service)

class Hosting(SantiagoMonitor):
    """List clients I'm hosting services for."""

    def get(self, *args, **kwargs):
        super(Hosting, self).get(*args, **kwargs)
        return { "clients": self.santiago.hosting.keys() }

    def put(self, client, *args, **kwargs):
        super(Hosting, self).put(client, *args, **kwargs)

        self.santiago.create_hosting_client(client)

    def delete(self, client, *args, **kwargs):
        super(Hosting, self).delete(client, *args, **kwargs)

        self.santiago.remove_hosting_client(client)

class HostedClient(SantiagoMonitor):
    """List the services I'm hosting for the client."""

    def get(self, client, *args, **kwargs):
        super(HostedClient, self).get(*args, **kwargs)

        return { "client": client,
                 "services": self.santiago.get_host_services(client) }

    def put(self, client, service, update, *args, **kwargs):
        super(HostedClient, self).put(client, service, update, *args, **kwargs)

        self.santiago.create_hosting_service(client, service, update)


    def delete(self, client, service, *args, **kwargs):
        super(HostedClient, self).delete(client, service, *args, **kwargs)

        self.santiago.remove_hosting_service(client, service)

class HostedService(SantiagoMonitor):
    """List locations I'm hosting the service for the client."""

    def get(self, client, service, *args, **kwargs):
        super(HostedService, self).get(client, service, *args, **kwargs)

        return {
            "service": service,
            "client": client,
            "locations": self.santiago.get_host_locations(client, service)}

    def put(self, client, service, location, update, *args, **kwargs):
        super(HostedService, self).put(client, service, location,
                                       *args, **kwargs)
        if(not isinstance(location, list)):
            location = [location]
        self.santiago.create_hosting_location(client, service, location, update)

    # Have to remove instead of delete for locations as ``service`` is a list
    def delete(self, client, service, location, *args, **kwargs):
        super(HostedService, self).delete(client, service, location,
                                          *args, **kwargs)

        self.santiago.remove_hosting_location(client, service, location)

class Consuming(SantiagoMonitor):
    """Get the hosts I'm consuming services from."""

    def get(self, *args, **kwargs):
        super(Consuming, self).get(*args, **kwargs)

        return { "hosts": self.santiago.consuming.keys() }

    def put(self, host, *args, **kwargs):
        super(Consuming, self).put(host, *args, **kwargs)

        self.santiago.create_consuming_host(host)

    def delete(self, host, *args, **kwargs):
        super(Consuming, self).delete(host, *args, **kwargs)

        self.santiago.remove_consuming_host(host)

class ConsumedHost(SantiagoMonitor):
    """Get the services I'm consuming from the host."""

    def get(self, host, *args, **kwargs):
        super(ConsumedHost, self).get(host, *args, **kwargs)

        return {
            "services": self.santiago.get_client_services(host),
            "host": host }

    def put(self, host, service, update, *args, **kwargs):
        super(ConsumedHost, self).put(host, service, update, *args, **kwargs)

        self.santiago.create_consuming_service(host, service, update)

    def delete(self, host, service, *args, **kwargs):
        super(ConsumedHost, self).delete(host, service, *args, **kwargs)

        self.santiago.remove_consuming_service(host, service)

class ConsumedService(SantiagoMonitor):
    """Get the locations of the service I'm consuming from the host."""

    def get(self, host, service, *args, **kwargs):
        super(ConsumedService, self).get(host, service, *args, **kwargs)

        return { "service": service,
                 "host": host,
                 "locations":
                     self.santiago.get_client_locations(host, service) }

    def put(self, host, service, location, update, *args, **kwargs):
        super(ConsumedService, self).put(host, service, location, update,
                                         *args, **kwargs)
        if(not isinstance(location, list)):
            location = [location]
        self.santiago.create_consuming_location(host, service, location, update)

    # Have to remove instead of delete for locations as $service is a list
    def delete(self, host, service, location, *args, **kwargs):
        super(ConsumedService, self).delete(host, service, location,
                                            *args, **kwargs)

        self.santiago.remove_consuming_location(host, service, location)


if __name__ == "__main__":
    if "-d" in sys.argv:
        DEBUG = 1
