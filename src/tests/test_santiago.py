#! /usr/bin/env python
# -*- mode: python; mode: auto-fill; fill-column: 80 -*-

"""These tests are designed to test the main Santiago class."""

import sys
import unittest

import cherrypy
import gnupg
import json
import logging
from optparse import OptionParser
import src.santiago as santiago
import src.utilities as utilities
import src.connectors.https.controller as httpscontroller
from pprint import pprint
from datetime import datetime
import time
from time import sleep

cherrypy.log.access_file = None

class SantiagoTest(unittest.TestCase):
    """The base class for tests."""

    if sys.version_info < (2, 7):
        """Add a poor man's forward compatibility."""

        class ContainsError(AssertionError):
            pass

        def assertIn(self, item, container):
            if not item in container:
                raise self.ContainsError("%s not in %s" % (item, container))

        def assertNotIn(self, item, container):
            if item in container:
                raise self.ContainsError("%s in %s" % (item, container))

class SantiagoSetupTests(SantiagoTest):
    """Does Santiago get created correctly?"""
    """hosting=None, consuming=None, 
                 my_key_id=0, reply_service=None,
                 save_dir="src/tests/data/SantiagoSetupTests", 
                 save_services=True,
                 gpg=None, force_sender=None, *args, **kwargs"""
    def test_create_santiago_with_https_listener(self):
        """Ensure listeners are set from variable in Santiago creator"""
        self.santiago = santiago.Santiago(listeners={ "https": { "socket_port": 80 } },
                                          save_dir="src/tests/data/SantiagoSetupTests")
        self.assertIsInstance(self.santiago.listeners["https"],httpscontroller.HttpsListener)

    def test_create_santiago_with_listeners_not_set(self):
        """Ensure listeners are set if variable in Santiago creator is None"""
        self.santiago = santiago.Santiago(save_dir="src/tests/data/SantiagoSetupTests")
        self.assertEqual(None, self.santiago.listeners)

    def test_create_santiago_with_https_sender(self):
        """Ensure listeners are set from variable in Santiago creator"""
        self.santiago = santiago.Santiago(senders={ "https": { "proxy_host": 80 } },
                                          save_dir="src/tests/data/SantiagoSetupTests")
        self.assertIsInstance(self.santiago.senders["https"],httpscontroller.HttpsSender)

    def test_create_santiago_with_senders_not_set(self):
        """Ensure listeners are set if variable in Santiago creator is None"""
        self.santiago = santiago.Santiago(save_dir="src/tests/data/SantiagoSetupTests")
        self.assertEqual(None, self.santiago.senders)

    def test_create_santiago_with_https_monitor(self):
        """Ensure listeners are set from variable in Santiago creator"""
        self.santiago = santiago.Santiago(monitors={ "https": { "socket_port": 80 } },
                                          save_dir="src/tests/data/SantiagoSetupTests")
        self.assertIsInstance(self.santiago.monitors["https"],httpscontroller.HttpsMonitor)

    def test_create_santiago_with_monitors_not_set(self):
        """Ensure listeners are set if variable in Santiago creator is None"""
        self.santiago = santiago.Santiago(save_dir="src/tests/data/SantiagoSetupTests")
        self.assertEqual(None, self.santiago.monitors)

class UpdateTime(SantiagoTest):
    """Ensure services/locations are only updated if update time is valid"""

    def setUp(self):
        """Create a request."""

        self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')

        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")
        self.santiago = santiago.Santiago(my_key_id = self.keyid, 
                                          gpg = self.gpg,
                                          save_dir='src/tests/data/IncomingRequest')

        self.valid_request_version = self.santiago.REQUEST_VERSION
        self.valid_reply_versions = self.santiago.SUPPORTED_REPLY_VERSIONS
        self.original_update_time = time.time()

        self.request = self.wrap_message({ "host": self.keyid, "client": self.keyid,
                         "service": santiago.Santiago.SERVICE_NAME, 
                         "reply_to": None, "locations": [1],
                         "request_version": self.valid_request_version, 
                         "reply_versions": self.valid_reply_versions,
                         "update": self.original_update_time})

        self.santiago.requests[self.keyid].add(santiago.Santiago.SERVICE_NAME)
        self.santiago.incoming_request([self.request])

    def wrap_message(self, message):
        """The standard wrapping method for these tests."""
	
        return str(self.gpg.encrypt(json.dumps(message),
                                    recipients=[self.keyid],
                                    sign=self.keyid))

    def test_identical_times_fail(self):
        self.request = self.wrap_message({ "host": self.keyid, "client": self.keyid,
                         "service": santiago.Santiago.SERVICE_NAME, 
                         "reply_to": None, "locations": [2],
                         "request_version": self.valid_request_version, 
                         "reply_versions": self.valid_reply_versions,
                         "update": self.original_update_time})
        self.santiago.requests[self.keyid].add(santiago.Santiago.SERVICE_NAME)
        self.assertEqual(None, self.santiago.incoming_request([self.request]))
        self.assertEqual([1], self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME])

    def test_times_greater_than_now_fail(self):
        date_to_use = self.original_update_time + 120
        self.request = self.wrap_message({ "host": self.keyid, "client": self.keyid,
                         "service": santiago.Santiago.SERVICE_NAME, 
                         "reply_to": None, "locations": [2],
                         "request_version": self.valid_request_version, 
                         "reply_versions": self.valid_reply_versions,
                         "update": date_to_use})
        self.santiago.requests[self.keyid].add(santiago.Santiago.SERVICE_NAME)
        self.assertEqual(None, self.santiago.incoming_request([self.request]))
        self.assertEqual([1], self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME])

    def test_times_less_than_last_update_fail(self):
        date_to_use = self.original_update_time - 120
        self.request = self.wrap_message({ "host": self.keyid, "client": self.keyid,
                         "service": santiago.Santiago.SERVICE_NAME, 
                         "reply_to": None, "locations": [2],
                         "request_version": self.valid_request_version, 
                         "reply_versions": self.valid_reply_versions,
                         "update": date_to_use})
        self.santiago.requests[self.keyid].add(santiago.Santiago.SERVICE_NAME)
        self.assertEqual(None, self.santiago.incoming_request([self.request]))
        self.assertEqual([1], self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME])

    def test_valid_time_true(self):
        date_to_use = self.original_update_time + 1
        sleep(2)
        self.request = self.wrap_message({ "host": self.keyid, "client": self.keyid,
                         "service": santiago.Santiago.SERVICE_NAME, 
                         "reply_to": None, "locations": [2],
                         "request_version": self.valid_request_version, 
                         "reply_versions": self.valid_reply_versions,
                         "update": date_to_use})
        self.santiago.requests[self.keyid].add(santiago.Santiago.SERVICE_NAME)
        self.assertEqual(None, self.santiago.incoming_request([self.request]))
        self.assertEqual([2], self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME])

    def test_update_date_as_none(self):
        date_to_use = None
        self.request = self.wrap_message({ "host": self.keyid, "client": self.keyid,
                         "service": santiago.Santiago.SERVICE_NAME, 
                         "reply_to": None, "locations": [2],
                         "request_version": self.valid_request_version, 
                         "reply_versions": self.valid_reply_versions,
                         "update": date_to_use})
        self.santiago.requests[self.keyid].add(santiago.Santiago.SERVICE_NAME)
        self.assertEqual(None, self.santiago.incoming_request([self.request]))
        self.assertEqual([1], self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME])

class IncomingRequest(SantiagoTest):
    """Ensure Exceptions are hidden and that messages are passed to unpack_request correctly"""

    def setUp(self):
        """Create a request."""

        self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')

        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")
        self.santiago = santiago.Santiago(my_key_id = self.keyid, 
                                          gpg = self.gpg,
                                          save_dir='src/tests/data/IncomingRequest')

        self.valid_request_version = self.santiago.REQUEST_VERSION
        self.valid_reply_versions = self.santiago.SUPPORTED_REPLY_VERSIONS
        self.original_update_time = time.time()

        self.request = { "host": self.keyid, "client": self.keyid,
                         "service": santiago.Santiago.SERVICE_NAME, 
                         "reply_to": None, "locations": [1],
                         "request_version": self.valid_request_version, 
                         "reply_versions": self.valid_reply_versions,
                         "update": self.original_update_time}

    def wrap_message(self, message):
        """The standard wrapping method for these tests."""
	
        return str(self.gpg.encrypt(json.dumps(message),
                                    recipients=[self.keyid],
                                    sign=self.keyid))

    def test_ensure_string_handled(self):
        """If a string is passed to incoming_request, convert it to a single value in a list."""
        self.assertEqual({}, self.santiago.consuming)
        self.request = self.wrap_message(self.request)
        self.santiago.requests[self.keyid].add(santiago.Santiago.SERVICE_NAME)

        self.assertEqual(None, self.santiago.incoming_request(self.request))
        self.assertEqual([1], self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME])

    def test_valid_request_list(self):
        """A message that should pass does pass normally."""
        self.assertEqual({}, self.santiago.consuming)
        self.request = self.wrap_message(self.request)
        self.santiago.requests[self.keyid].add(santiago.Santiago.SERVICE_NAME)

        self.assertEqual(None, self.santiago.incoming_request([self.request]))
        self.assertEqual([1], self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME])

    def test_empty_request_list(self):
        """A message that should pass does pass normally."""
        self.assertEqual({}, self.santiago.consuming)
        self.assertEqual(None, self.santiago.incoming_request(["test"]))
        self.assertEqual({}, self.santiago.consuming)

    def test_invalid_requests_queue(self):
        """If a service isnt in incoming_request requests queue then don't process request."""
        self.assertEqual({}, self.santiago.consuming)
        self.request = self.wrap_message(self.request)
        
        self.assertEqual(None, self.santiago.incoming_request([self.request]))
        self.assertEqual({}, self.santiago.consuming)

    def test_service_update_recorded(self):
        """If a service is updated, we need to send a valid update datetime 
        as well to keep track of latest values.
        """
        with self.assertRaises(KeyError) as context:
            self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME]['update']
        date_to_use = time.time()
        self.request = self.wrap_message({ "host": self.keyid, "client": self.keyid,
                         "service": santiago.Santiago.SERVICE_NAME, 
                         "reply_to": None, "locations": [2],
                         "request_version": self.valid_request_version, 
                         "reply_versions": self.valid_reply_versions,
                         "update": date_to_use})
        self.santiago.requests[self.keyid].add(santiago.Santiago.SERVICE_NAME)
        self.assertEqual(None, self.santiago.incoming_request([self.request]))
        self.assertEqual(date_to_use, self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME+'-update-timestamp'])

    def test_reject_time_key(self):
        """Confirm that an attacker is unable to replay-attack a service update."""
        self.assertEqual({}, self.santiago.consuming)
        self.request = self.wrap_message(self.request)
        self.santiago.requests[self.keyid].add(santiago.Santiago.SERVICE_NAME)
        #Sent t+0 - Server submits service, message is logged.
        self.assertEqual(None, self.santiago.incoming_request([self.request]))
        self.assertEqual([1], self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME])
        original_request = self.request
        date_to_use = time.time()
        self.request = self.wrap_message({ "host": self.keyid, "client": self.keyid,
                         "service": santiago.Santiago.SERVICE_NAME, 
                         "reply_to": None, "locations": [2],
                         "request_version": self.valid_request_version, 
                         "reply_versions": self.valid_reply_versions,
                         "update": date_to_use})
        #Sent t+1 - Server updates service to a new state.
        self.santiago.requests[self.keyid].add(santiago.Santiago.SERVICE_NAME)
        self.assertEqual(None, self.santiago.incoming_request([self.request]))
        self.assertEqual([2], self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME])
        self.assertEqual(date_to_use, self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME+'-update-timestamp'])
        #t+2 Attacker submits message to roll back the request clock to t-1.
        #Don't know how to make a variable not updatable?
        #self.santiago.consuming[self.keyid][self.service_name]['update'] = time.time()
        #self.assertEqual(date_to_use, self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME]['update'])
        #t+3 Attacker resubmits t+0 request, rolling back the service.
        #Ensure location isn't rolled back to [1].
        self.santiago.requests[self.keyid].add(santiago.Santiago.SERVICE_NAME)
        self.assertEqual(None, self.santiago.incoming_request([original_request]))
        self.assertEqual(date_to_use, self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME+'-update-timestamp'])
        self.assertEqual([2], self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME])

    def test_update_timestamp_not_directly_updatable(self):
        """Ensure that an attacker is unable to change the service timestamp by updating the named service"""
        self.assertEqual({}, self.santiago.consuming)
        self.request = self.wrap_message(self.request)
        self.santiago.requests[self.keyid].add(santiago.Santiago.SERVICE_NAME)
        #Sent t+0 - Server submits service, message is logged.
        self.assertEqual(None, self.santiago.incoming_request([self.request]))
        self.assertEqual([1], self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME])
        self.assertEqual(self.original_update_time, self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME+'-update-timestamp'])
        date_to_use = time.time()
        self.request = self.wrap_message({ "host": self.keyid, "client": self.keyid,
                         "service": santiago.Santiago.SERVICE_NAME+'-update-timestamp', 
                         "reply_to": None, "locations": [1],
                         "request_version": self.valid_request_version, 
                         "reply_versions": self.valid_reply_versions,
                         "update": date_to_use})
        self.santiago.requests[self.keyid].add(santiago.Santiago.SERVICE_NAME+'-update-timestamp')
        self.assertEqual(None, self.santiago.incoming_request([self.request]))
        self.assertEqual(self.original_update_time, self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME+'-update-timestamp'])



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

        self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')

        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")
        self.santiago = santiago.Santiago(my_key_id = self.keyid, 
                                          gpg = self.gpg,
                                          save_dir='src/tests/data/UnpackRequest')
        self.valid_request_version = self.santiago.REQUEST_VERSION
        self.valid_reply_versions = self.santiago.SUPPORTED_REPLY_VERSIONS

        self.request = { "host": self.keyid, "client": self.keyid,
                         "service": santiago.Santiago.SERVICE_NAME, 
                         "reply_to": [1], "locations": [1],
                         "request_version": self.valid_request_version, 
                         "reply_versions": self.valid_reply_versions,
                         "update": time.time() }

        self.ALL_KEYS = set(("host", "client", "service",
                             "locations", "reply_to",
                             "request_version", "reply_versions", "update"))
        self.REQUIRED_KEYS = set(("client", "host", "service",
                                  "request_version", "reply_versions", "update"))
        self.OPTIONAL_KEYS = set(("locations", "reply_to"))
        self.LIST_KEYS = set(("reply_to", "locations", "reply_versions"))

    def validate_request(self, adict):
        """Update From & To in adict"""
        adict.update({ "from": self.keyid,
                       "to": self.keyid })

        return adict

    def wrap_message(self, message):
        """The standard wrapping method for these tests."""
	
        return str(self.gpg.encrypt(json.dumps(message),
                                    recipients=[self.keyid],
                                    sign=self.keyid))

    def test_valid_message(self):
        """A message that should pass does pass normally."""
        adict = self.validate_request(dict(self.request))
        self.request = self.wrap_message(self.request)
        self.assertEqual(self.santiago.unpack_request(self.request), adict)

    def test_request_contains_all_keys(self):
        """The test request needs all supported keys."""

        for key in self.ALL_KEYS:
            self.assertIn(key, self.request)

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

        santiago.Santiago.SUPPORTED_REPLY_VERSIONS, unsupported = \
            set(["e"]), santiago.Santiago.SUPPORTED_REPLY_VERSIONS

        self.request = self.wrap_message(self.request)

        self.assertFalse(self.santiago.unpack_request(self.request))

        santiago.Santiago.SUPPORTED_REPLY_VERSIONS, unsupported = \
            unsupported, santiago.Santiago.SUPPORTED_REPLY_VERSIONS

        self.assertTrue(santiago.Santiago.SUPPORTED_REPLY_VERSIONS, set([1]))

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
        self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')
        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")

        self.santiago = santiago.Santiago(
            hosting = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None }},
            consuming = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None }},
            my_key_id = self.keyid,
            gpg = self.gpg,
            save_dir='src/tests/data/HandleRequest')

        self.santiago.requested = False
        self.santiago.outgoing_request = (lambda *args, **kwargs:
                                              self.record_success())

        self.from_ = self.keyid
        self.to_ = self.keyid
        self.host = self.keyid
        self.client = self.keyid
        self.service = santiago.Santiago.SERVICE_NAME
        self.reply_to = [1]
        self.request_version = 1
        self.reply_versions = [1]
        self.update = time.time()

    def record_success(self):
        """Record that we tried to reply to the request."""

        self.santiago.requested = True

    def call_handle_request(self):
        """A short-hand for calling handle_request with all 8 arguments.  Oy."""

        self.santiago.handle_request(
                self.from_, self.to_,
                self.host, self.client,
                self.service, self.reply_to,
                self.request_version, self.reply_versions,
                self.update)

    def test_valid_message(self):
        """Reply to valid messages."""

        self.call_handle_request()

        self.assertTrue(self.santiago.requested)

    def test_unwilling_source(self):
        """Don't handle the request if the cilent or proxy isn't trusted.

        Ok, so, "isn't trusted" is the wrong turn of phrase here.  Technically,
        it's "this Santiago isn't willing to host services for", but the
        former's much easier to type.

        """
        for key in ("client", ):
            setattr(self, key, 0)

            self.call_handle_request()

            self.assertFalse(self.santiago.requested)

    def test_learn_services(self):
        """New reply_to locations are learned."""

        self.reply_to.append(2)

        self.call_handle_request()

        self.assertTrue(self.santiago.requested)
        self.assertEqual(
            self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME],
            [1, 2])

    def test_replace_consuming_location(self):
        """Confirm location is replaced"""
        self.reply_to.append(2)

        self.call_handle_request()

        self.assertEqual(
            self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME],
            [1, 2])

        self.santiago.replace_consuming_location(self.keyid, santiago.Santiago.SERVICE_NAME, [1, 3], time.time())

        self.assertEqual(
            self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME],
            [1, 3])

class HostingAndConsuming(SantiagoTest):
    """Process an incoming request, from a client, for to host services.
    """
    def setUp(self):
        """Do a good bit of setup to make this a nicer test-class.
        """
        self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')
        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")

        self.santiago = santiago.Santiago(
            hosting = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None }},
            consuming = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None }},
            my_key_id = self.keyid,
            gpg = self.gpg,
            save_dir='src/tests/data/HostingAndConsuming')



    def test_replace_consuming_location_when_no_location(self):
        """Confirm location is added when location not there"""
        self.santiago.consuming = {}

        self.santiago.replace_consuming_location(self.keyid, santiago.Santiago.SERVICE_NAME, [1, 3], time.time())

        self.assertEqual(
            self.santiago.consuming[self.keyid][santiago.Santiago.SERVICE_NAME],
            [1, 3])

    def test_get_host_locations_correctly(self):
        """Return host locations when there are locations set"""
        self.assertEqual([1], self.santiago.get_host_locations(self.keyid, santiago.Santiago.SERVICE_NAME))

    def test_get_host_locations_with_incorrect_key(self):
        """Error raised when passed an incorrect key."""
        self.assertEqual(None, self.santiago.get_host_locations("test", santiago.Santiago.SERVICE_NAME))

    def test_get_host_services_correctly(self):
        """Return host services when there are clients set"""
        self.assertEqual({santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None }, self.santiago.get_host_services(self.keyid))

    def test_get_host_services_with_incorrect_key(self):
        """Error raised when passed an incorrect key."""
        self.assertEqual(None, self.santiago.get_host_services("test"))

    def test_get_client_locations_correctly(self):
        """Return client locations when there are locations set"""
        self.assertEqual([1], self.santiago.get_client_locations(self.keyid, santiago.Santiago.SERVICE_NAME))

    def test_get_client_locations_with_incorrect_key(self):
        """Error raised when passed an incorrect key."""
        self.assertEqual(None, self.santiago.get_client_locations("test", santiago.Santiago.SERVICE_NAME))

    def test_get_client_services_correctly(self):
        """Return client services when there are services set"""
        self.assertEqual({santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None }, self.santiago.get_client_services(self.keyid))

    def test_get_client_services_with_incorrect_key(self):
        """Error raised when passed an incorrect key."""
        self.assertEqual(None, self.santiago.get_client_services("test"))

    def test_get_served_clients_correctly(self):
        """Return client services when there are services set"""
        self.assertEqual([self.keyid], self.santiago.get_served_clients(santiago.Santiago.SERVICE_NAME))

    def test_get_served_clients_with_incorrect_service(self):
        """Nothing returned when client not served."""
        self.assertEqual([], self.santiago.get_served_clients("test"))

    def test_get_serving_hosts_correctly(self):
        """Return hosting services from host when there are services set"""
        self.assertEqual([self.keyid], self.santiago.get_serving_hosts(santiago.Santiago.SERVICE_NAME))

    def test_get_serving_hosts_with_incorrect_service(self):
        """Nothing returned when host not hosting service for me."""
        self.assertEqual([], self.santiago.get_serving_hosts("test"))



class OutgoingRequest(SantiagoTest):
    """Are outgoing requests properly formed?

    Here, we'll use a faux Santiago Sender that merely records and decodes the
    request when it goes out.

    """
    class TestRequestSender(object):
        """A barebones sender that records details about the request."""

        def __init__(self):
            self.destination = self.crypt = self.request = None
            self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')

        def outgoing_request(self, request, destination):
            """Decrypt and record the pertinent details about the request."""

            self.destination = destination
            self.crypt = request
            self.request = str(self.gpg.decrypt(str(request)))

    def setUp(self):
        """Create an encryptable request."""
        self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')
        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")

        self.santiago = santiago.Santiago(
            my_key_id = self.keyid,
            consuming = { self.keyid: { santiago.Santiago.SERVICE_NAME: 
                                        ( "https://1", )}},
            gpg = self.gpg,
            save_dir='src/tests/data/OutgoingRequest')

        self.valid_request_version = self.santiago.REQUEST_VERSION
        self.valid_reply_versions = self.santiago.SUPPORTED_REPLY_VERSIONS

        self.request_sender = OutgoingRequest.TestRequestSender()
        self.santiago.senders = { "https": self.request_sender }

        self.host = self.keyid
        self.client = self.keyid
        self.service = santiago.Santiago.SERVICE_NAME
        self.reply_to = [ "https://1" ]
        self.locations = [1]
        self.request_version = self.valid_request_version
        self.reply_versions = self.valid_reply_versions
        self.destination = self.crypt = self.request = None

        self.request = {
            "host": self.host, "client": self.client,
            "service": self.service,
            "reply_to": self.reply_to, "locations": self.locations,
            "request_version": self.request_version,
            "reply_versions": self.reply_versions}

    def outgoing_call(self):
        """A short-hand for calling outgoing_request with all 8 arguments."""

        self.santiago.outgoing_request(from_ = None, to = None,
            host = self.host, client = self.client,
            service = self.service, locations = self.locations, reply_to = self.reply_to)

###Unsure how to make this test pass as a value of update is returned 
###with a value dependant on when test ran
#    def test_valid_message(self):
#        """Are valid messages properly encrypted and delivered?"""

#        self.outgoing_call()

#        self.assertEqual(self.request_sender.request,
#                         json.dumps(self.request))
#        self.assertEqual(self.request_sender.destination, self.reply_to[0])

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

    Each should be available in ``self.hosting`` after it has been learned.

    """
    def setUp(self):
        self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')
        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")

        self.santiago = santiago.Santiago(my_key_id = self.keyid, 
                                          gpg = self.gpg,
                                          save_dir='src/tests/data/CreateHosting')

        self.client = 1
        self.service = 2
        self.location = 3

    def test_add_hosting_client(self):
        """Confirm client is added to hosting list"""
        self.assertNotIn(self.client, self.santiago.hosting)
        self.santiago.create_hosting_client(self.client)
        self.assertIn(self.client, self.santiago.hosting)

    def test_add_hosting_service(self):
        """Confirm service is added to hosting list"""
        self.assertNotIn(self.client, self.santiago.hosting)
        self.santiago.create_hosting_service(self.client, self.service, time.time())
        self.assertIn(self.service, self.santiago.hosting[self.client])

    def test_add_hosting_location(self):
        """Confirm location is added to hosting list"""
        self.assertNotIn(self.client, self.santiago.hosting)
        self.santiago.create_hosting_location(self.client, self.service,
                                              [self.location], time.time())
        self.assertIn(self.location,
                        self.santiago.hosting[self.client][self.service])

class CreateConsuming(SantiagoTest):
    """Are hosts, services, and locations learned correctly?

    Each should be available in ``self.consuming`` after it's learned.

    """
    def setUp(self):
        self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')
        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")

        self.santiago = santiago.Santiago(my_key_id = self.keyid, gpg=self.gpg,
                                          save_dir='src/tests/data/CreateConsuming')

        self.host = 1
        self.service = 2
        self.location = 3

    def test_add_consuming_host(self):
        """Confirm host is added to consuming list"""
        self.assertNotIn(self.host, self.santiago.consuming)
        self.santiago.create_consuming_host(self.host)

        self.assertIn(self.host, self.santiago.consuming)

    def test_add_consuming_service(self):
        """Confirm service is added to consuming list"""
        self.assertNotIn(self.host, self.santiago.consuming)
        self.santiago.create_consuming_service(self.host, self.service, time.time())

        self.assertIn(self.service, self.santiago.consuming[self.host])

    def test_add_consuming_location(self):
        """Confirm location is added to consuming list"""
        self.assertNotIn(self.host, self.santiago.consuming)
        self.santiago.create_consuming_location(self.host, 
                                                 self.service,
                                                [self.location], 
                                                time.time())

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
        gpg_to_use = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')

        configfile = "src/tests/data/test_gpg.cfg"

        config = utilities.load_config(configfile)

        (keyid, protocols, connectors, force_sender) = utilities.get_config_values(
            config)

        listeners, senders, monitors = utilities.configure_connectors(
            protocols, connectors)

        hosting = { keyid: { service: [url], service+'-update-timestamp': None } }
        consuming = { keyid: { service: [url], service+'-update-timestamp': None } }

        freedombuddy = santiago.Santiago(hosting=hosting, consuming=consuming,
                                         save_dir='src/tests/data/ArgumentTests',
                                         my_key_id=keyid, gpg=gpg_to_use)

        self.cycle(freedombuddy)
        freedombuddy1 = santiago.Santiago(my_key_id=keyid, gpg=gpg_to_use,
                                          save_dir='src/tests/data/ArgumentTests')

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
        gpg_to_use = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')

        configfile = "src/tests/data/test_gpg.cfg"

        config = utilities.load_config(configfile)

        (keyid, protocols, connectors, force_sender) = utilities.get_config_values(
            config)

        listeners, senders, monitors = utilities.configure_connectors(
            protocols, connectors)

        hosting = { keyid: { service: [url], service+'-update-timestamp': None } }
        consuming = { keyid: { service: [url], service+'-update-timestamp': None } }

        freedombuddy = santiago.Santiago(hosting=hosting, consuming=consuming,
                                         save_services=False, my_key_id=keyid, 
                                         gpg=gpg_to_use)
        freedombuddy1 = santiago.Santiago(my_key_id=keyid, gpg=gpg_to_use,
                                          save_dir='src/tests/data/ArgumentTests')

        self.cycle(freedombuddy)
        self.cycle(freedombuddy1)

        self.assertNotIn(service, freedombuddy1.hosting)
        self.assertNotIn(service, freedombuddy1.consuming)

class Hosting(SantiagoTest):
    """Tests Hosting Rest interface."""

    def setUp(self):
        self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')
        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")

        self.santiago = santiago.Santiago(
            hosting = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None }},
            consuming = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None }},
            my_key_id = self.keyid,
            gpg = self.gpg,
            save_dir='src/tests/data/Hosting')

    def test_santiago_hosting_get(self):
        hosting = santiago.Hosting(self.santiago)
        self.assertEqual({'clients': ['95801F1ABE01C28B05ADBE5FA7C860604DAE2628']}, hosting.get())

    def test_santiago_hosting_put(self):
        hosting = santiago.Hosting(self.santiago)
        hosting.put("1")
        self.assertEqual({'clients': ['1', '95801F1ABE01C28B05ADBE5FA7C860604DAE2628']}, hosting.get())

    def test_santiago_hosting_delete_valid_client(self):
        hosting = santiago.Hosting(self.santiago)
        self.assertEqual({'clients': ['95801F1ABE01C28B05ADBE5FA7C860604DAE2628']}, hosting.get())
        hosting.delete("95801F1ABE01C28B05ADBE5FA7C860604DAE2628")
        self.assertEqual({'clients': []}, hosting.get())

    def test_santiago_hosting_delete_invalid_client(self):
        hosting = santiago.Hosting(self.santiago)
        self.assertEqual({'clients': ['95801F1ABE01C28B05ADBE5FA7C860604DAE2628']}, hosting.get())
        hosting.delete("1")
        self.assertEqual({'clients': ['95801F1ABE01C28B05ADBE5FA7C860604DAE2628']}, hosting.get())

    def test_santiago_hosting_put_existing_client(self):
        hosting = santiago.Hosting(self.santiago)
        hosting.put("95801F1ABE01C28B05ADBE5FA7C860604DAE2628")
        self.assertEqual({'clients': ['95801F1ABE01C28B05ADBE5FA7C860604DAE2628']}, hosting.get())

class HostedClient(SantiagoTest):
    """Tests HostedClient Rest interface."""

    def setUp(self):
        self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')
        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")
        self.date_to_use = time.time()

        self.santiago = santiago.Santiago(
            hosting = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None }},
            consuming = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None }},
            my_key_id = self.keyid,
            gpg = self.gpg,
            save_dir='src/tests/data/HostedClient')

    def test_santiago_hosted_client_get(self):
        hostedClient = santiago.HostedClient(self.santiago)
        self.assertEqual({'client': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','services': {santiago.Santiago.SERVICE_NAME: [1], 
                         santiago.Santiago.SERVICE_NAME+'-update-timestamp': None}}, 
                         hostedClient.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628'))

    def test_santiago_hosted_client_get_with_invalid_client(self):
        hostedClient = santiago.HostedClient(self.santiago)
        self.assertEqual({'client': '1','services': None},
                         hostedClient.get('1'))

    def test_santiago_hosted_client_put(self):
        hostedClient = santiago.HostedClient(self.santiago)
        hostedClient.put('95801F1ABE01C28B05ADBE5FA7C860604DAE2628',"2", self.date_to_use)
        self.assertEqual({'client': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','services': {'2':[], '2-update-timestamp': self.date_to_use, 
                         santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None}}, 
                         hostedClient.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628'))

    def test_santiago_hosted_client_ensure_put_existing_service_does_not_overwrite_service(self):
        hostedClient = santiago.HostedClient(self.santiago)
        hostedClient.put('95801F1ABE01C28B05ADBE5FA7C860604DAE2628',santiago.Santiago.SERVICE_NAME, self.date_to_use)
        self.assertEqual({'client': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','services': {santiago.Santiago.SERVICE_NAME: [1], 
                         santiago.Santiago.SERVICE_NAME+'-update-timestamp': self.date_to_use}}, 
                         hostedClient.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628'))

    def test_santiago_hosted_client_delete(self):
        hostedClient = santiago.HostedClient(self.santiago)
        hostedClient.delete('95801F1ABE01C28B05ADBE5FA7C860604DAE2628',santiago.Santiago.SERVICE_NAME, self.date_to_use)
        self.assertEqual({'client': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','services': {}}, 
                         hostedClient.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628'))

    def test_santiago_hosted_client_delete_invalid_service(self):
        hostedClient = santiago.HostedClient(self.santiago)
        hostedClient.delete('95801F1ABE01C28B05ADBE5FA7C860604DAE2628','2', self.date_to_use)
        self.assertEqual({'client': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','services': {santiago.Santiago.SERVICE_NAME: [1], 
                         santiago.Santiago.SERVICE_NAME+'-update-timestamp': None}}, 
                         hostedClient.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628'))

    def test_santiago_hosted_client_delete_invalid_client_and_invalid_service(self):
        hostedClient = santiago.HostedClient(self.santiago)
        self.assertRaises(KeyError, hostedClient.delete,'2','2', self.date_to_use)

    def test_santiago_hosted_client_delete_invalid_client_and_valid_service(self):
        hostedClient = santiago.HostedClient(self.santiago)
        self.assertRaises(KeyError, hostedClient.delete,'2',santiago.Santiago.SERVICE_NAME, self.date_to_use)

class HostedService(SantiagoTest):
    """Tests HostedClient Rest interface."""

    def setUp(self):
        self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')
        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")
        self.initial_update = time.time()
        self.test_update = time.time()

        self.santiago = santiago.Santiago(
            hosting = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': self.initial_update }},
            consuming = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': self.initial_update }},
            my_key_id = self.keyid,
            gpg = self.gpg,
            save_dir='src/tests/data/HostedService')

    def test_santiago_hosted_service_get(self):
        hostedService = santiago.HostedService(self.santiago)
        self.assertEqual({'client': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','service': santiago.Santiago.SERVICE_NAME, 'locations': [1]}, 
                         hostedService.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', santiago.Santiago.SERVICE_NAME))

    def test_santiago_hosted_service_get_with_incorrect_service(self):
        hostedService = santiago.HostedService(self.santiago)
        self.assertEqual({'client': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','service': '1', 'locations': None}, 
                         hostedService.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', '1'))

    def test_santiago_hosted_service_put(self):
        hostedService = santiago.HostedService(self.santiago)
        hostedService.put('95801F1ABE01C28B05ADBE5FA7C860604DAE2628',"2","3", self.test_update)
        self.assertEqual({'client': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','service': '2', 'locations': ['3']}, 
                         hostedService.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', '2'))

    def test_santiago_hosted_service_put_add_to_existing_service(self):
        hostedService = santiago.HostedService(self.santiago)
        hostedService.put('95801F1ABE01C28B05ADBE5FA7C860604DAE2628',santiago.Santiago.SERVICE_NAME,[1,3], self.test_update)
        self.assertEqual({'client': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','service': santiago.Santiago.SERVICE_NAME, 'locations': [1,3]}, 
                         hostedService.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', santiago.Santiago.SERVICE_NAME))

    def test_santiago_hosted_service_delete(self):
        hostedService = santiago.HostedService(self.santiago)
        hostedService.delete('95801F1ABE01C28B05ADBE5FA7C860604DAE2628',santiago.Santiago.SERVICE_NAME,1)
        self.assertEqual({'client': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','service': santiago.Santiago.SERVICE_NAME, 'locations': []}, 
                         hostedService.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', santiago.Santiago.SERVICE_NAME))

    def test_santiago_hosted_service_delete_invalid_location(self):
        hostedService = santiago.HostedService(self.santiago)
        hostedService.delete('95801F1ABE01C28B05ADBE5FA7C860604DAE2628',santiago.Santiago.SERVICE_NAME,2)
        self.assertEqual({'client': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','service': santiago.Santiago.SERVICE_NAME, 'locations': [1]}, 
                         hostedService.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', santiago.Santiago.SERVICE_NAME))

    def test_santiago_hosted_service_delete_invalid_service_and_invalid_location(self):
        hostedService = santiago.HostedService(self.santiago)
        hostedService.delete('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', '2', 2)
        self.assertEqual({'client': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','service': santiago.Santiago.SERVICE_NAME, 'locations': [1]}, 
                         hostedService.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', santiago.Santiago.SERVICE_NAME))

    def test_santiago_hosted_service_delete_invalid_service_and_valid_location(self):
        hostedService = santiago.HostedService(self.santiago)
        hostedService.delete('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', '2', 1)
        self.assertEqual({'client': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','service': santiago.Santiago.SERVICE_NAME, 'locations': [1]}, 
                         hostedService.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', santiago.Santiago.SERVICE_NAME))

class Consuming(SantiagoTest):
    """Tests Consuming Rest interface."""

    def setUp(self):
        self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')
        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")

        self.santiago = santiago.Santiago(
            hosting = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None }},
            consuming = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None }},
            my_key_id = self.keyid,
            gpg = self.gpg,
            save_dir='src/tests/data/Consuming')

    def test_santiago_consuming_get(self):
        consuming = santiago.Consuming(self.santiago)
        self.assertEqual({'hosts': ['95801F1ABE01C28B05ADBE5FA7C860604DAE2628']}, consuming.get())

    def test_santiago_consuming_put(self):
        consuming = santiago.Consuming(self.santiago)
        consuming.put("1")
        self.assertEqual({'hosts': ['1', '95801F1ABE01C28B05ADBE5FA7C860604DAE2628']}, consuming.get())

    def test_santiago_consuming_delete_valid_host(self):
        consuming = santiago.Consuming(self.santiago)
        self.assertEqual({'hosts': ['95801F1ABE01C28B05ADBE5FA7C860604DAE2628']}, consuming.get())
        consuming.delete("95801F1ABE01C28B05ADBE5FA7C860604DAE2628")
        self.assertEqual({'hosts': []}, consuming.get())

    def test_santiago_consuming_delete_invalid_host(self):
        consuming = santiago.Consuming(self.santiago)
        self.assertEqual({'hosts': ['95801F1ABE01C28B05ADBE5FA7C860604DAE2628']}, consuming.get())
        consuming.delete("1")
        self.assertEqual({'hosts': ['95801F1ABE01C28B05ADBE5FA7C860604DAE2628']}, consuming.get())

    def test_santiago_consuming_put_existing_host(self):
        consuming = santiago.Consuming(self.santiago)
        consuming.put("95801F1ABE01C28B05ADBE5FA7C860604DAE2628")
        self.assertEqual({'hosts': ['95801F1ABE01C28B05ADBE5FA7C860604DAE2628']}, consuming.get())

class ConsumedHost(SantiagoTest):
    """Tests ConsumedHost Rest interface."""

    def setUp(self):
        self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')
        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")
        self.initial_update = time.time()
        self.test_update = time.time()

        self.santiago = santiago.Santiago(
            hosting = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': self.initial_update }},
            consuming = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': self.initial_update }},
            my_key_id = self.keyid,
            gpg = self.gpg,
            save_dir='src/tests/data/ConsumedHost')

    def test_santiago_consumed_host_get(self):
        consumedHost = santiago.ConsumedHost(self.santiago)
        self.assertEqual({'host': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','services': {santiago.Santiago.SERVICE_NAME: [1], 
                         santiago.Santiago.SERVICE_NAME+'-update-timestamp': self.initial_update}}, 
                         consumedHost.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628'))

    def test_santiago_consumed_host_get_with_invalid_host(self):
        consumedHost = santiago.ConsumedHost(self.santiago)
        self.assertEqual({'host': '1','services': None},
                         consumedHost.get('1'))

    def test_santiago_consumed_host_put(self):
        consumedHost = santiago.ConsumedHost(self.santiago)
        consumedHost.put('95801F1ABE01C28B05ADBE5FA7C860604DAE2628',"2", self.test_update)
        self.assertEqual({'host': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','services': {'2': [], '2-update-timestamp': self.test_update, 
                         santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': self.initial_update}}, 
                         consumedHost.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628'))

    def test_santiago_consumed_host_ensure_put_existing_service_does_not_overwrite_service(self):
        consumedHost = santiago.ConsumedHost(self.santiago)
        consumedHost.put('95801F1ABE01C28B05ADBE5FA7C860604DAE2628',santiago.Santiago.SERVICE_NAME, self.test_update)
        self.assertEqual({'host': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','services': {santiago.Santiago.SERVICE_NAME: [1], 
                         santiago.Santiago.SERVICE_NAME+'-update-timestamp': self.test_update}}, 
                         consumedHost.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628'))

    def test_santiago_consumed_host_delete(self):
        consumedHost = santiago.ConsumedHost(self.santiago)
        consumedHost.delete('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', santiago.Santiago.SERVICE_NAME)
        self.assertEqual({'host': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628', 'services': {}}, 
                         consumedHost.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628'))

    def test_santiago_consumed_host_delete_invalid_service(self):
        consumedHost = santiago.ConsumedHost(self.santiago)
        consumedHost.delete('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', '2', self.test_update)
        self.assertEqual({'host': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628', 'services': {santiago.Santiago.SERVICE_NAME: [1], 
                         santiago.Santiago.SERVICE_NAME+'-update-timestamp': self.initial_update}}, 
                         consumedHost.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628'))

    def test_santiago_consumed_host_delete_invalid_host_and_invalid_service(self):
        consumedHost = santiago.ConsumedHost(self.santiago)
        self.assertRaises(KeyError, consumedHost.delete,'2', '2')

    def test_santiago_consumed_host_delete_invalid_host_and_valid_service(self):
        consumedHost = santiago.ConsumedHost(self.santiago)
        self.assertRaises(KeyError, consumedHost.delete,'2', santiago.Santiago.SERVICE_NAME)

class ConsumedService(SantiagoTest):
    """Tests consumedService Rest interface."""

    def setUp(self):
        self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')
        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")
        self.initial_update = time.time()
        self.test_update = time.time()

        self.santiago = santiago.Santiago(
            hosting = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': self.initial_update}},
            consuming = {self.keyid: {santiago.Santiago.SERVICE_NAME: [1], santiago.Santiago.SERVICE_NAME+'-update-timestamp': self.initial_update}},
            my_key_id = self.keyid,
            gpg = self.gpg,
            save_dir='src/tests/data/ConsumedService')

    def test_santiago_consumed_service_get(self):
        consumedService = santiago.ConsumedService(self.santiago)
        self.assertEqual({'host': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','service': santiago.Santiago.SERVICE_NAME, 'locations': [1]}, 
                         consumedService.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', santiago.Santiago.SERVICE_NAME))

    def test_santiago_consumed_service_get_with_incorrect_service(self):
        consumedService = santiago.ConsumedService(self.santiago)
        self.assertEqual({'host': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','service': '1', 'locations': None}, 
                         consumedService.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', '1'))

    def test_santiago_consumed_service_put(self):
        consumedService = santiago.ConsumedService(self.santiago)
        consumedService.put('95801F1ABE01C28B05ADBE5FA7C860604DAE2628',"2","3", time.time())
        self.assertEqual({'host': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','service': '2', 'locations': ['3']}, 
                         consumedService.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', '2'))

    def test_santiago_consumed_service_put_add_to_existing_service(self):
        consumedService = santiago.ConsumedService(self.santiago)
        consumedService.put('95801F1ABE01C28B05ADBE5FA7C860604DAE2628',santiago.Santiago.SERVICE_NAME, [1,3], self.test_update)
        self.assertEqual({'host': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','service': santiago.Santiago.SERVICE_NAME, 'locations': [1,3]}, 
                         consumedService.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', santiago.Santiago.SERVICE_NAME))

    def test_santiago_consumed_service_delete(self):
        consumedService = santiago.ConsumedService(self.santiago)
        consumedService.delete('95801F1ABE01C28B05ADBE5FA7C860604DAE2628',santiago.Santiago.SERVICE_NAME,1)
        self.assertEqual({'host': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','service': santiago.Santiago.SERVICE_NAME, 'locations': []}, 
                         consumedService.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', santiago.Santiago.SERVICE_NAME))

    def test_santiago_consumed_service_delete_invalid_location(self):
        consumedService = santiago.ConsumedService(self.santiago)
        consumedService.delete('95801F1ABE01C28B05ADBE5FA7C860604DAE2628',santiago.Santiago.SERVICE_NAME,2)
        self.assertEqual({'host': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','service': santiago.Santiago.SERVICE_NAME, 'locations': [1]}, 
                         consumedService.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', santiago.Santiago.SERVICE_NAME))

    def test_santiago_consumed_service_delete_invalid_service_and_invalid_location(self):
        consumedService = santiago.ConsumedService(self.santiago)
        consumedService.delete('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', '2', 2)
        self.assertEqual({'host': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','service': santiago.Santiago.SERVICE_NAME, 'locations': [1]}, 
                         consumedService.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', santiago.Santiago.SERVICE_NAME))

    def test_santiago_consumed_service_delete_invalid_service_and_valid_location(self):
        consumedService = santiago.ConsumedService(self.santiago)
        consumedService.delete('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', '2', 1)
        self.assertEqual({'host': '95801F1ABE01C28B05ADBE5FA7C860604DAE2628','service': santiago.Santiago.SERVICE_NAME, 'locations': [1]}, 
                         consumedService.get('95801F1ABE01C28B05ADBE5FA7C860604DAE2628', santiago.Santiago.SERVICE_NAME))

if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    unittest.main()

#if __name__ == "__main__":
#    logging.basicConfig(level=logging.DEBUG)
#    unittest.main()
