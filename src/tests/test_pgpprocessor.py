#! /usr/bin/env python # -*- mode: auto-fill; fill-column: 80 -*-

"""Tests for the PGP Processing Tools.

All aspects of each PGP processor should be fully tested: this verifies
identity, allowing trust to exist in the system.  If this is mucked up, trust
isn't verifiable.

"""

import gnupg
import pgpprocessor
import unittest
import utilities
from utilities import InvalidSignatureError

def remove_line(string, line, preserve_newlines = True):
    """Remove a line from a multi-line string."""

    if preserve_newlines and not line.endswith("\n"):
        line += "\n"

    return str(string.splitlines(preserve_newlines).remove(line))

class RevokedKey(unittest.TestCase):
    """self.gpg_revoked_then_valid should have valid key {1} and valid key {2}
       self.gpg_revoked should have valid key {2} and revoked public key for {1}
    """

    def setUp(self):
        valid = 'data/test_revoked_keys/test_revoked_then_valid_keys/'
        revoked = 'data/test_revoked_keys/test_still_revoked_keys/'
        revoked_config = 'data/test_revoked_keys/test_revoked_then_valid.cfg'
        self.iterations = 3
        self.gpg_expired_then_valid = gnupg.GPG(gnupghome=valid)
        self.gpg_expired = gnupg.GPG(gnupghome=revoked)
        self.config = utilities.load_config(revoked_config)

class RevokedKeyTest(RevokedKey):
    """Confirm that data signed with expired keys is not decrypted"""

    def setUp(self):
        super(RevokedKeyTest, self).setUp()

        self.key_id = utilities.safe_load(self.config, "pgpprocessor", 
                                          "keyid", 0)
        self.messages = utilities.multi_sign(
            gpg = self.gpg_expired_then_valid,
            iterations = self.iterations,
            keyid = self.key_id)

        self.unwrapper = pgpprocessor.Unwrapper(self.messages[-1],
                                                self.gpg_expired)

    def test_unwrap_fails_when_message_signed_by_revoked_key(self):
        """Should fail as invalid signature as the key the data was signed 
        with is revoked in gpg"""

        self.assertRaises(InvalidSignatureError, self.unwrapper.next)

class ValidSubKeyButRevokedSuperKeyTest(RevokedKey):
    """Confirm that data signed with revoked keys is not decrypted"""

    def setUp(self):
        super(ValidSubKeyButRevokedSuperKeyTest, self).setUp()

        self.key_id = utilities.safe_load(self.config, "pgpprocessor", 
                                          "sub_keyid", 0)
        self.messages = utilities.multi_sign(
            gpg = self.gpg_expired_then_valid,
            iterations = self.iterations,
            keyid = self.key_id)

        self.unwrapper = pgpprocessor.Unwrapper(self.messages[-1],
                                                self.gpg_expired)

    def test_message_failure_signed_by_valid_sub_key_but_revoked_key(self):
        """Should fail as invalid signature as the super key the data was 
        signed with is revoked in gpg"""

        self.assertRaises(InvalidSignatureError, self.unwrapper.next)

class ExpiredKey(unittest.TestCase):
    """self.gpg_expired_then_valid should have 
    valid key {455D3FB8823783253D804B218E42A4A8F15A9174} and 
    valid key {E68BE6A2E5B52E7DD0BED889CE1405033F743EB9}
    self.gpg_expired should have 
    valid key {E68BE6A2E5B52E7DD0BED889CE1405033F743EB9} and 
    expired public key for {455D3FB8823783253D804B218E42A4A8F15A9174}
    """

    def setUp(self):
        valid = 'data/test_expired_keys/test_expired_then_valid_keys/'
        expired = 'data/test_expired_keys/test_still_expired_keys/'
        expired_config = 'data/test_expired_keys/test_expired_then_valid.cfg'
        self.iterations = 3
        self.gpg_expired_then_valid = gnupg.GPG(gnupghome=valid)
        self.gpg_expired = gnupg.GPG(gnupghome=expired)
        self.config = utilities.load_config(expired_config)

class ValidSubKeyButExpiredSuperKeyTest(ExpiredKey):
    """Confirm that data signed with expired keys is not decrypted"""

    def setUp(self):
        super(ValidSubKeyButExpiredSuperKeyTest, self).setUp()

        self.key_id = utilities.safe_load(self.config, "pgpprocessor", 
                                          "sub_keyid", 0)
        self.messages = utilities.multi_sign(
            gpg = self.gpg_expired_then_valid,
            iterations = self.iterations,
            keyid = self.key_id)

        self.unwrapper = pgpprocessor.Unwrapper(self.messages[-1],
                                                self.gpg_expired)

    def test_message_failure_signed_by_valid_sub_key_but_expired_key(self):
        """Should fail as invalid signature as the super key the data was 
        signed with is expired in gpg"""

        self.assertRaises(InvalidSignatureError, self.unwrapper.next)

class ExpiredKeyTest(ExpiredKey):
    """Confirm that data signed with expired keys is not decrypted"""

    def setUp(self):
        super(ExpiredKeyTest, self).setUp()

        self.key_id = utilities.safe_load(self.config, "pgpprocessor", 
                                          "keyid", 0)
        self.messages = utilities.multi_sign(
            gpg = self.gpg_expired_then_valid,
            iterations = self.iterations,
            keyid = self.key_id)

        self.unwrapper = pgpprocessor.Unwrapper(self.messages[-1],
                                                self.gpg_expired)

    def test_unwrap_fails_when_message_signed_by_expired_key(self):
        """Should fail as invalid signature as the key the data was signed 
        with is expired in gpg"""

        self.assertRaises(InvalidSignatureError, self.unwrapper.next)

class MessageWrapper(unittest.TestCase):
    """Basic setup for message-signing tests.

    These tests would run much faster if I could use setUpClass (>30x faster:
    signing three messages for each test consumes lots of entropy that needs to
    be rebuilt?), but that's a Python 2.7 feature.  I'll rewrite this when
    Debian Stable includes Python 2.7 or Python 3.X.  It's much prettier.

    """
    def setUp(self):

        self.iterations = 3
        self.gpg = gnupg.GPG(gnupghome='data/test_gpg_home')
        config = utilities.load_config("data/test.cfg")
        self.key_id = utilities.safe_load(config, "pgpprocessor", "keyid", 0)
        self.messages = utilities.multi_sign(
            gpg = self.gpg,
            iterations = self.iterations,
	    keyid = self.key_id)

class UnwrapperTest(MessageWrapper):
    """Verify that we can unwrap multiply-signed PGP messages correctly."""

    def setUp(self):
        super(UnwrapperTest, self).setUp()

        self.unwrapper = pgpprocessor.Unwrapper(self.messages[-1],
                                                self.gpg)

    def test_messages_wrapped(self):
        """Were the messages correctly wrapped in the first place?"""

        self.assertEqual(self.iterations + 1, len(self.messages))

    def test_reset_fields(self):
        """Confirm all variables are cleared by reset function"""
        self.unwrapper.body = "test_body"
        self.unwrapper.start = "test_start"
        self.unwrapper.header = "test_header"
        self.unwrapper.footer = "test_footer"
        self.unwrapper.end = "test_end"
        self.unwrapper.gpg_data = "test_gpg_data"
        self.assertEqual(self.unwrapper.body, "test_body")
        self.assertEqual(self.unwrapper.start, "test_start")
        self.assertEqual(self.unwrapper.header, "test_header")
        self.assertEqual(self.unwrapper.footer, "test_footer")
        self.assertEqual(self.unwrapper.end, "test_end")
        self.assertEqual(self.unwrapper.gpg_data, "test_gpg_data")
        self.unwrapper.reset_fields()
        self.assertEqual(self.unwrapper.body, [])
        self.assertEqual(self.unwrapper.start, [])
        self.assertEqual(self.unwrapper.header, [])
        self.assertEqual(self.unwrapper.footer, [])
        self.assertEqual(self.unwrapper.end, [])
        self.assertEqual(self.unwrapper.gpg_data, None)

    def test_unwrap_all_messages(self):
        """Do we unwrap the right number of messages?"""

        # count each element in the iterator once, skipping the first.
        self.assertEqual(self.iterations, sum([1 for e in self.unwrapper]))

    def test_dont_uwrap(self):
        """Creating an unwrapper shouldn't unwrap the message.

        Only iterating through the unwrapper should unwrap it.  We don't want to
        process the message at all until we're explicitly told to do so.

        """
        self.assertEqual(self.unwrapper.message, self.messages[-1])
        self.assertEqual(str(self.unwrapper).strip(), "")

    def test_iterator_unwraps_correctly(self):
        """The iterator should correctly unwrap each stage of the message."""
        unwrapped_messages = self.messages[:-1]

        for message in reversed(unwrapped_messages):
            self.unwrapper.next()
            self.assertEqual(message.strip(), self.unwrapper.message.strip())

    def test_no_header_invalid(self):
        """Messages without heads are considered invalid."""

        self.unwrapper.message = remove_line(
            self.unwrapper.message, "-----BEGIN PGP SIGNED MESSAGE-----\n")

        self.assertRaises(StopIteration, self.unwrapper.next)

    def test_no_body_invalid(self):
        """Messages without bodies are considered invalid."""

        self.unwrapper.message = remove_line(self.unwrapper.message, "\n")

        self.assertRaises(StopIteration, self.unwrapper.next)

    def test_no_footer_invalid(self):
        """Messages without feet are considered invalid."""

        self.unwrapper.message = remove_line(
            self.unwrapper.message, "-----BEGIN PGP SIGNATURE-----\n")

        self.assertRaises(StopIteration, self.unwrapper.next)

    def test_no_end_invalid(self):
        """Messages without tails are considered invalid."""

        self.unwrapper.message = remove_line(
            self.unwrapper.message, "-----END PGP SIGNATURE-----\n")

        self.assertRaises(StopIteration, self.unwrapper.next)


if __name__ == "__main__":
    unittest.main()
