#! /usr/bin/env python # -*- mode: auto-fill; fill-column: 80 -*-
from pprint import pprint
import gnupg
import santiago
import utilities
import unittest

class GnuPGWrapper(unittest.TestCase):
    """Basic setup for message-signing tests.

    These tests would run much faster if I could use setUpClass (>30x faster:
    signing three messages for each test consumes lots of entropy that needs to
    be rebuilt?), but that's a Python 2.7 feature.  I'll rewrite this when
    Debian Stable includes Python 2.7 or Python 3.X.  It's much prettier.

    """
    def setUp(self):

        self.gpg = gnupg.GPG(gnupghome='../data/test_gpg_home')
        config = utilities.load_config()
        self.key_id = utilities.safe_load(config, "pgpprocessor", "keyid", 0)
        self.recipient = "joe@foo.bar"
        self.message = {'lol': 'cats'}

class CryptionTest(GnuPGWrapper):
    """Verify that we can unwrap multiply-signed PGP messages correctly."""

    def setUp(self):
        super(CryptionTest, self).setUp()

    def test_encrypt_then_decrypt(self):

    	#Encrypt data
    	encrypted_data = self.gpg.encrypt(str(self.message), self.recipient)
    	#Decrypt data
    	decrypted_data = self.gpg.decrypt(str(encrypted_data))
    	#Test decrypted is same as original
    	self.assertEqual(str(self.message), str(decrypted_data))

    def test_sign_then_verify(self):
    	signed = self.gpg.sign(str(self.message),keyid=self.key_id)
	verified = self.gpg.verify(str(signed.data))
	self.assertEqual(verified.fingerprint,self.key_id)
	self.assertEqual(True,verified.valid)

if __name__ == "__main__":
    unittest.main()

