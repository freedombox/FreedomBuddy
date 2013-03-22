#! /usr/bin/env python
# -*- mode: python; mode: auto-fill; fill-column: 80 -*-

"""These tests are designed to test the main Santiago class."""

import os
import sys
import unittest

import cherrypy
import gnupg
import json
import logging
from optparse import OptionParser
import santiago, santiago_test
import utilities


cherrypy.log.access_file = None

class SantiagoTest(unittest.TestCase):
    """The base class for tests."""

    if sys.version_info < (2, 7):
        """Add a poor man's forward compatibility."""

        class ContainsError(AssertionError):
            pass

        def assertIn(self, a, b):
            if not a in b:
                raise self.ContainsError("%s not in %s" % (a, b))

        def assertNotIn(self, a, b):
            if a in b:
                raise self.ContainsError("%s in %s" % (a, b))


class UnpackRequest(SantiagoTest):

    """Are requests unpacked as expected?

    - Messages that aren't for me (that I can't decrypt) are ignored.
    - Messages with invalid signatures are rejected.
    - Only passing messages return the dictionary.
    - Each message identifies the Santiago protocol version it uses.
    - Messages come with a range of Santiago protocol versions I can reply with.
    - Messages that don't share any of my versions are ignored (either the
      client or I won't be able to understand the message).
    - The message is unpacked correctly.  This is a bit difficult because of the
      number of overlapping data types.

      First, we have the keys that must be present in each message:

      - client
      - host
      - service
      - locations
      - reply_to
      - request_version
      - reply_versions

      Next the list-keys which must be lists (they'll later be converted
      directly to sets):

      - reply_to
      - locations
      - reply_versions

      Finally, we have the keys that may be empty:

      - locations
      - reply_to

      ``locations`` is empty on an incoming (request) message, while
      ``reply_to`` may be assumed if the reply destinations haven't changed
      since the previous message.  If they have, and the client still doesn't
      send the reply_to, then the host will be unable to communicate with it, so
      it's in the client's best interests to send it whenever reasonable.

      So, the structure of a message is a little weird here.  We have three sets
      of overlapping requirements:

      #. Certain keys must be present.
      #. Certain keys must be lists.
      #. Certain keys may be unset.

      The really odd ones out are "locations" and "reply_to", which fall into
      all three categories.

    """
    def setUp(self):
        """Create a request."""

        self.gpg = gnupg.GPG(gnupghome='../data/test_gpg_home')

        self.keyid = utilities.load_config().get("pgpprocessor", "keyid")
        self.santiago = santiago.Santiago(me = self.keyid, gpg = self.gpg)

        self.request = { "host": self.keyid, "client": self.keyid,
                         "service": santiago.Santiago.SERVICE_NAME, "reply_to": [1],
                         "locations": [1],
                         "request_version": 1, "reply_versions": [1], }

        self.ALL_KEYS = set(("host", "client", "service",
                             "locations", "reply_to",
                             "request_version", "reply_versions"))
        self.REQUIRED_KEYS = set(("client", "host", "service",
                                  "request_version", "reply_versions"))
        self.OPTIONAL_KEYS = set(("locations", "reply_to"))
        self.LIST_KEYS = set(("reply_to", "locations", "reply_versions"))

    def test_valid_message(self):
        """A message that should pass does pass normally."""

        adict = self.validate_request(dict(self.request))
        self.request = self.wrap_message(self.request)

        self.assertEqual(self.santiago.unpack_request(self.request), adict)

    def validate_request(self, adict):
        adict.update({ "from": self.keyid,
                       "to": self.keyid })

        return adict

    def test_request_contains_all_keys(self):
        """The test request needs all supported keys."""

        for key in self.ALL_KEYS:
            self.assertIn(key, self.request)

    def wrap_message(self, message):
        """The standard wrapping method for these tests."""
	
        return str(self.gpg.encrypt(json.dumps(message),
                                    recipients=[self.keyid],
                                    sign=self.keyid))

    def test_key_lists_updated(self):
        """Are the lists of keys up-to-date?"""

        for key in ("ALL_KEYS", "REQUIRED_KEYS", "OPTIONAL_KEYS", "LIST_KEYS"):
            self.assertEqual(getattr(self, key),
                             getattr(santiago.Santiago, key))

    def test_all_keys_accounted_for(self):
        """All the keys in the ALL_KEYS list are either required or optional."""

        self.assertEqual(set(self.ALL_KEYS),
                         set(self.REQUIRED_KEYS) | set(self.OPTIONAL_KEYS))

    def test_requred_keys_are_required(self):
        """If any required keys are missing, the message is skipped."""

        for key in self.ALL_KEYS:
            broken_dict = dict(self.request)
            del broken_dict[key]
            encrypted_data = self.wrap_message(broken_dict)

            self.assertEqual(self.santiago.unpack_request(encrypted_data), None)

    def test_non_null_keys_are_set(self):
        """If any keys that can't be empty are empty, the message is skipped."""

        for key in self.REQUIRED_KEYS:
            broken_dict = dict(self.request)
            broken_dict[key] = None
            encrypted_data = self.wrap_message(broken_dict)

            self.assertEqual(self.santiago.unpack_request(encrypted_data), None)

    def test_null_keys_are_null(self):
        """If any optional keys are null, the message's still processed."""

        for key in self.OPTIONAL_KEYS:
            broken_dict = dict(self.request)
            broken_dict[key] = None

            encrypted_data = self.wrap_message(broken_dict)

            broken_dict = self.validate_request(broken_dict)

            self.assertEqual(self.santiago.unpack_request(encrypted_data),
                             broken_dict)

    def test_skip_undecryptable_messages(self):
        """Mesasges that I can't decrypt (for other folks) are skipped.

        I don't know how I'll encrypt to a key that isn't there though.

        """
        pass

    def test_skip_invalid_signatures(self):
        """Messages with invalid signatures are skipped."""

        self.request = self.wrap_message(self.request)

        # delete the 7th line for the fun of it.
        mangled = self.request.splitlines(True)
        del mangled[7]
        self.request = "".join(mangled)

        self.assertEqual(self.santiago.unpack_request(self.request), None)

    def test_incoming_lists_are_lists(self):
        """Any variables that must be lists, before processing, actually are."""

        for key in self.LIST_KEYS:
            broken_request = dict(self.request)
            broken_request[key] = 1
            broken_request = self.wrap_message(broken_request)

            self.assertEqual(self.santiago.unpack_request(broken_request), None)

    def test_require_protocol_version_overlap(self):
        """Clients that can't accept protocols I can send are ignored."""

        santiago.Santiago.SUPPORTED_CONNECTORS, unsupported = \
            set(["e"]), santiago.Santiago.SUPPORTED_CONNECTORS

        self.request = self.wrap_message(self.request)

        self.assertFalse(self.santiago.unpack_request(self.request))

        santiago.Santiago.SUPPORTED_CONNECTORS, unsupported = \
            unsupported, santiago.Santiago.SUPPORTED_CONNECTORS

        self.assertTrue(santiago.Santiago.SUPPORTED_CONNECTORS, set([1]))

    def test_require_protocol_version_understanding(self):
        """The service must ignore any protocol versions it can't understand."""

        self.request["request_version"] = "e"

        self.request = self.wrap_message(self.request)

        self.assertFalse(self.santiago.unpack_request(self.request))

class HandleRequest(SantiagoTest):
    """Process an incoming request, from a client, for to host services.

    - Verify we're willing to host for both the client and proxy.  If we
      aren't, quit and return nothing.
    - Forward the request if it's not for me.
    - Learn new Santiagi if they were sent.
    - Reply to the client on the appropriate protocol.

    """
    def setUp(self):
        """Do a good bit of setup to make this a nicer test-class.

        Successful tests will call ``Santiago.outgoing_request``, so that's
        overridden to record that the method is called.

        """
	self.gpg = gnupg.GPG(gnupghome='../data/test_gpg_home')
        self.keyid = utilities.load_config().get("pgpprocessor", "keyid")

        self.santiago = santiago.Santiago(
            hosting = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1] }},
            consuming = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1] }},
            me = self.keyid,
	    gpg = self.gpg)

        self.santiago.requested = False
        self.santiago.outgoing_request = (lambda *args, **kwargs:
                                              self.record_success())

        self.from_ = self.keyid
        self.to = self.keyid
        self.host = self.keyid
        self.client = self.keyid
        self.service = santiago.Santiago.SERVICE_NAME
        self.reply_to = [1]
        self.request_version = 1
        self.reply_versions = [1]

    def record_success(self):
        """Record that we tried to reply to the request."""

        self.santiago.requested = True

    def test_call(self):
        """A short-hand for calling handle_request with all 8 arguments.  Oy."""

        self.santiago.handle_request(
                self.from_, self.to,
                self.host, self.client,
                self.service, self.reply_to,
                self.request_version, self.reply_versions)

    def test_valid_message(self):
        """Reply to valid messages."""

        self.test_call()

        self.assertTrue(self.santiago.requested)

    def test_unwilling_source(self):
        """Don't handle the request if the cilent or proxy isn't trusted.

        Ok, so, "isn't trusted" is the wrong turn of phrase here.  Technically,
        it's "this Santiago isn't willing to host services for", but the
        former's much easier to type.

        """
        for key in ("client", ):
            setattr(self, key, 0)

            self.test_call()

            self.assertFalse(self.santiago.requested)

    def test_learn_services(self):
        """New reply_to locations are learned."""

        self.reply_to.append(2)

        self.test_call()

        self.assertTrue(self.santiago.requested)
        self.assertEqual(
            self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME],
            [1, 2])

class OutgoingRequest(SantiagoTest):
    """Are outgoing requests properly formed?

    Here, we'll use a faux Santiago Sender that merely records and decodes the
    request when it goes out.

    """
    class TestRequestSender(object):
        """A barebones sender that records details about the request."""

        def __init__(self):
            self.gpg = gnupg.GPG(gnupghome='../data/test_gpg_home')

        def outgoing_request(self, request, destination):
            """Decrypt and record the pertinent details about the request."""

            self.destination = destination
            self.crypt = request
            self.request = str(self.gpg.decrypt(str(request)))

    def setUp(self):
        """Create an encryptable request."""
	self.gpg = gnupg.GPG(gnupghome='../data/test_gpg_home')
        self.keyid = utilities.load_config().get("pgpprocessor", "keyid")

        self.santiago = santiago.Santiago(
            me = self.keyid,
            consuming = { self.keyid: { santiago.Santiago.SERVICE_NAME: ( "https://1", )}},
	    gpg = self.gpg)

        self.request_sender = OutgoingRequest.TestRequestSender()
        self.santiago.senders = { "https": self.request_sender }

        self.host = self.keyid
        self.client = self.keyid
        self.service = santiago.Santiago.SERVICE_NAME
        self.reply_to = [ "https://1" ]
        self.locations = [1]
        self.request_version = 1
        self.reply_versions = [1]

        self.request = {
            "host": self.host, "client": self.client,
            "service": self.service,
            "reply_to": self.reply_to, "locations": self.locations,
            "request_version": self.request_version,
            "reply_versions": self.reply_versions }

    def outgoing_call(self):
        """A short-hand for calling outgoing_request with all 8 arguments."""

        self.santiago.outgoing_request(
            None, None, self.host, self.client,
            self.service, self.locations, self.reply_to)

    def test_valid_message(self):
        """Are valid messages properly encrypted and delivered?"""

        self.outgoing_call()

        self.assertEqual(self.request_sender.request,
                         json.dumps(self.request))
        self.assertEqual(self.request_sender.destination, self.reply_to[0])

    def test_queue_service_request(self):
        """Add the host's service to the request queue."""

        self.outgoing_call()

        self.assertIn(self.service, self.santiago.requests[self.host])

    def test_transparent_unwrapping(self):
        """Is the unwrapping process transparent?"""

        import urlparse, urllib

        self.outgoing_call()

        request = {"request": str(self.request_sender.crypt) }

        self.assertEqual(request["request"],
                         urlparse.parse_qs(urllib.urlencode(request))
                         ["request"][0])

class CreateHosting(SantiagoTest):
    """Are clients, services, and locations learned correctly?

    Each should be available in ``self.hosting`` after it's learned.

    """
    def setUp(self):
	self.gpg = gnupg.GPG(gnupghome='../data/test_gpg_home')
        self.keyid = utilities.load_config().get("pgpprocessor", "keyid")

        self.santiago = santiago.Santiago(me = self.keyid, gpg = self.gpg)

        self.client = 1
        self.service = 2
        self.location = 3

    def test_add_hosting_client(self):
        self.santiago.create_hosting_client(self.client)
        self.assertIn(self.client, self.santiago.hosting)

    def test_add_hosting_service(self):
        self.santiago.create_hosting_service(self.client, self.service)
        self.assertIn(self.service, self.santiago.hosting[self.client])

    def test_add_hosting_location(self):
        self.santiago.create_hosting_location(self.client, self.service,
                                              [self.location])
        self.assertIn(self.location,
                        self.santiago.hosting[self.client][self.service])

class CreateConsuming(SantiagoTest):
    """Are hosts, services, and locations learned correctly?

    Each should be available in ``self.consuming`` after it's learned.

    """
    def setUp(self):
	self.gpg = gnupg.GPG(gnupghome='../data/test_gpg_home')
        self.keyid = utilities.load_config().get("pgpprocessor", "keyid")

        self.santiago = santiago.Santiago(me = self.keyid, gpg=self.gpg)

        self.host = 1
        self.service = 2
        self.location = 3

    def test_add_consuming_host(self):
        self.santiago.create_consuming_host(self.host)

        self.assertIn(self.host, self.santiago.consuming)

    def test_add_consuming_service(self):
        self.santiago.create_consuming_service(self.host, self.service)

        self.assertIn(self.service, self.santiago.consuming[self.host])

    def test_add_consuming_location(self):
        self.santiago.create_consuming_location(self.host,self.service,
                                                [self.location])

        self.assertIn(self.location,
                       self.santiago.consuming[self.host][self.service])

class ArgumentTests(SantiagoTest):
    """Tests arguments to the FreedomBuddy service."""

    def cycle(self, freedombuddy):
        """Send a FreedomBuddy host through its entire lifecycle."""

        freedombuddy.live = 0
        with freedombuddy:
            pass

    def test_saving_services(self):
        """Are services correctly saved?"""

        url = "sharky_with_angry_hats"
        service = "omg its a fake service name, haha."
        gpg_to_use = gnupg.GPG(gnupghome='../data/test_gpg_home')

        options = OptionParser()
        options.config = "../data/test.cfg"

        (keyid, protocols, connectors, force_sender) = santiago_test.load_config(
            options)

        listeners, senders, monitors = santiago_test.configure_connectors(
            protocols, connectors)

        hosting = { keyid: { service: [url] } }
        consuming = { keyid: { service: [url] } }

        freedombuddy = santiago.Santiago(hosting=hosting, consuming=consuming,
                                         save_dir='../data/test_gpg_home',
                                         me=keyid, gpg=gpg_to_use)

        self.cycle(freedombuddy)
        freedombuddy1 = santiago.Santiago(me=keyid, gpg=gpg_to_use,
                                          save_dir='../data/test_gpg_home')

        self.assertIn(service, freedombuddy1.hosting[keyid])
        self.assertIn(service, freedombuddy1.consuming[keyid])

    def test_forgetting_services(self):
        """Are services correctly forgotten?

        Technically, this means "never saved."

        Chances are good my fake service names won't ever be real services, so
        unless somebody's trying to outsmart the test, there's nothing to worry
        about.

        """
        url = "sharky_with_angry_hats"
        service = "omg its a fake service name, haha."
        gpg_to_use = gnupg.GPG(gnupghome='../data/test_gpg_home')

        options = OptionParser()
        options.config = "../data/test.cfg"

        (keyid, protocols, connectors,force_sender) = santiago_test.load_config(
            options)

        listeners, senders, monitors = santiago_test.configure_connectors(
            protocols, connectors)

        hosting = { keyid: { service: [url] } }
        consuming = { keyid: { service: [url] } }

        freedombuddy = santiago.Santiago(hosting=hosting, consuming=consuming,
                                         save_services=False, me=keyid, gpg=gpg_to_use)
        freedombuddy1 = santiago.Santiago(me=keyid, gpg=gpg_to_use)

        self.cycle(freedombuddy)
        self.cycle(freedombuddy1)

        self.assertNotIn(service, freedombuddy1.hosting)
        self.assertNotIn(service, freedombuddy1.consuming)


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    unittest.main()
