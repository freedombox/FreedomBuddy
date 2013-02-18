#! /usr/bin/python

"""Tests for the FreedomBuddy Location reporter.

Tests enforce the behaviors documented in ``freedombuddy.py``.

Unfortunately, we can't test command-line argument errors.  ``parser.error``
quits the interpreter, so testing stops whenever we test an error condition.

"""

import gnupg
import subprocess
import unittest

import connectors.cli.controller

class OutgoingRequest(unittest.TestCase):

    def setUp(self):
        self.gpg = gnupg.GPG(use_agent = True)
        self.request = gpg.encrypt(json.dumps(
                { "host": 1, "client": 2,
                  "service": 3, "locations": [4]
                  "reply_to": [5]
                  "request_version": 1,
                  "reply_versions": [1],}),
                                   host, sign=self.me)
        self.sender = controller.Sender()

    def test_quote_objects(self):
        """Quoting objects should not error.

        Objects should be properly stringified.

        """
        destination = "https://localhost:8080"
        self.assertEqual(None,
                         self.sender.outgoing_request(self.request,
                                                      destination))


class ValidateArgs(unittest.TestCase):
    """Verify argument combinations.

    Verify that valid argument combinations are accepted and that invalid ones
    are rejected.

    """
    def setUp(self):
        self.parser = optparse.OptionParser()

    def test_outgoing_request_accepts_both(self):
        """Outgoing request requires all of -q, -k, and -d."""
        (options, args) = controller.interpret_args(
            ["-q", "-k 12345", "-d 12345"],
            self.parser)

        self.assertIsNone(validate_args(options, self.parser))

    def test_outgoing_request_requires_both(self):
        """Outgoing request rejects only one of -q, -k or -d."""

        options = ["-q", "-o 12345", "-d 12345"]

        for x in range(len(options)):
            # munge a copy of the option list.
            munge = options[:]
            del munge[x]

            (options, args) = controller.interpret_args(
                self.parser)

            self.assertRaises(optparse.OptionError,
                              controller.validate_args(options, self.parser))

# Here be dragons...
#
# I don't know what in here will actually run.

class ArgumentInterpretation(unittest.TestCase):
    """Verify arguments set data as expected.

    Might as well test: if I muck this up, it'll be really hard to debug.

    """
    def arg_verify(self, arg_name, short_name=None, destination=None, value=0,
                   boolean=False):
        """Make sure that arguments taking values save those values correctly.

        If the shortname or destination isn't supplied, it'll be interpreted
        from the long name by using the second and third

        If the value is a boolean flag, don't pass the target value as an
        argument.

        """
        if short_name is None:
            short_name = "-" + arg_name[0]

        if destination is None:
            destination = arg_name

        for name in (short_name, "--" + arg_name):
            args = [name, value] if not boolean else [name]

            (options, args) = freedombuddy.interpret_args(args)

            self.assertEqual(getattr(options, destination), value)

    def test_key(self):
        """Do ``-k`` and ``--key`` set ``options.key``?"""

        self.arg_verify("key")

    def test_service(self):
        """Do ``-s`` and ``--service`` set ``options.service``?"""

        self.arg_verify("service")

    def test_timeout(self):
        """Do ``-t`` and ``--timeout`` set ``options.timeout``?"""

        self.arg_verify("timeout")

    def test_address(self):
        """Do ``-a`` and ``--address`` set ``options.address``?"""

        self.arg_verify("address")

    def test_port(self):
        """Do ``-p`` and ``--port`` set ``options.port``?"""

        self.arg_verify("port")

    def test_host(self):
        """Do ``-o`` and ``--host`` set ``options.host`` to True?"""

        self.arg_verify("host", short_name="-o", value=True, boolean=True)

    def test_client(self):
        """Do ``-c`` and ``--client`` set ``options.host`` to False?"""

        self.arg_verify("client", destination="host", value=False, boolean=True)

    def test_noquery(self):
        """Do ``-n`` and ``--no-query`` set ``options.query`` to False?"""

        self.arg_verify("no-query", destination="query", value=False,
                        boolean=True)

    def test_forcequery(self):
        """Do ``-f`` and ``--force-query`` set ``options.query`` to True?"""

        self.arg_verify("force-query", destination="query", value=True,
                        boolean=True)

    def test_unset_host(self):
        """Does passing neither ``--host`` nor ``--client`` set ``options.host``
        to True?

        """
        (options, args) = freedombuddy.interpret_args([])

        self.assertEqual(options.host, True)

    def test_unset_host(self):
        """Does passing neither ``--no-query`` nor ``--force-query`` set
        ``options.query`` to None?

        """
        (options, args) = freedombuddy.interpret_args([])

        self.assertEqual(options.query, None)

class FreedomBuddyTest(unittest.TestCase):
    """Utility functions to do the boring work.

    In the tradition of DRY, DDTBWMTO:

        Don't do the boring work more than once.

    """
    def setUp(self, *args, **kwargs):
        super(FreedomBuddyTest, self).setUp(*args, **kwargs)

        url = "sharky_with_angry_hats"
        service = "omg its a fake service name, haha."

        listeners = senders = None
        hosting = { keyid: { service: [url] } }
        consuming = { keyid: { service: [url] } }

        freedombuddy = santiago.Santiago(listeners, senders,
            hosting, consuming,
            save_services=False, me=keyid)

    def host(self, user, key, value):
        """Host the key with the value for the user."""

        # FIXME replace with socket communications.
        conn = httplib.HTTPSConnection("localhost", 8080)
        freedombuddy.communicate(conn, "hosting", key, value, "POST")
        pass

class LocalQuery(FreedomBuddyTest):
    """Are local FreedomBuddies queried correctly?

    If I've set up a FreedomBuddy service, I should be able to pull data from
    it.

    """
    def setUp(self):
        super(LocalQuery, self).setUp(*args, **kwargs)
        pass

class RemoteQuery(FreedomBuddyTest):
    """Are remote FreedomBuddies queried correctly?

    If I know of another FreedomBuddy service, I should be able to pull data
    from it.

    """
    pass

class LocalRemoteInteractions(FreedomBuddyTest):
    """Do local and remote FreedomBuddies interact as expected?"""

    def test_learn_service(self):
        """Can we ask a remote Buddy for a service successfully?

        When querying remote buddies for services we know they host for us, we
        should learn the data and report it.

        """
        pass

if __name__ == "__main__":
    unittest.main()
