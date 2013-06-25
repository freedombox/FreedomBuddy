#! /usr/bin/env python # -*- mode: auto-fill; fill-column: 80 -*-

"""Tests for the Utilities functions.

These functions are mostly tested by testing completed on main Santiago functionality but these should be tested independantly as well.

"""

import unittest
import src.utilities as utilities
import gnupg
from ConfigParser import NoSectionError
from src.utilities import GPGNotSpecifiedError
from src.utilities import GPGKeyNotSpecifiedError
from datetime import datetime, timedelta

"""Need to test get_config_values / configure_connectors / multi_sign"""


class LoadConfig(unittest.TestCase):
    """Reads in correct data from config file.
    """

    def setUp(self):
        self.config_to_use = 'src/tests/data/test_gpg.cfg'

    def test_confirm_config_loaded_from_correct_file(self):
        self.config = utilities.load_config(self.config_to_use)
        self.assertEqual("95801F1ABE01C28B05ADBE5FA7C860604DAE2628", self.config.get("pgpprocessor","keyid"))

    def test_confirm_error_raised_if_config_file_does_not_exist(self):
        self.config = utilities.load_config('d')
        self.assertRaises(NoSectionError, self.config.get,"pgpprocessor","keyid")

class SafeLoad(unittest.TestCase):
    """Reads in correct data from specified config file. If sections/keys aren't in config file, a default value is returned.
    """

    def setUp(self):
        self.config_to_use = 'src/tests/data/test_gpg.cfg'

    def test_correct_value_returned_from_config_file(self):
        self.config = utilities.load_config(self.config_to_use)
        self.assertEqual("95801F1ABE01C28B05ADBE5FA7C860604DAE2628", utilities.safe_load(self.config,"pgpprocessor","keyid"))

    def test_default_value_returned_from_config_file_with_incorrect_key(self):
        self.config = utilities.load_config(self.config_to_use)
        self.assertEqual(None, utilities.safe_load(self.config,"pgpprocessor","incorrectly_named_key_in_section"))

    def test_correct_section_returned_from_config_file(self):
        self.config = utilities.load_config(self.config_to_use)
        self.assertEqual([('keyid', '95801F1ABE01C28B05ADBE5FA7C860604DAE2628')], utilities.safe_load(self.config,"pgpprocessor"))

    def test_default_value_returned_from_config_file_with_incorrect_section(self):
        self.config = utilities.load_config(self.config_to_use)
        self.assertEqual(None, utilities.safe_load(self.config,"incorrectly_named_section"))

    def test_None_returned_if_config_file_does_not_exist_and_default_value_not_set(self):
        self.config = utilities.load_config('d')
        self.assertEqual(None, utilities.safe_load(self.config,"pgpprocessor","keyid"))

    def test_default_value_returned_if_config_file_does_not_exist(self):
        self.config = utilities.load_config('d')
        self.assertEqual("test", utilities.safe_load(self.config,"pgpprocessor","keyid","test"))

class MultiSign(unittest.TestCase):
    """Helper function to sign a message a number of times with a certain key"""

    def setUp(self):
        self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')

    def test_incorrect_gpg_raises_error(self):
        self.assertRaises(GPGNotSpecifiedError, utilities.multi_sign, message="Test Message", gpg=None, keyid="1")

    def test_incorrect_gpg_key_raises_error(self):
        self.assertRaises(GPGKeyNotSpecifiedError, utilities.multi_sign, message="Test Message", gpg=self.gpg, keyid=None)

class ConfigureConnectors(unittest.TestCase):
    """Helper function retrieve create connectors with specified values"""

    def setUp(self):
        self.config = "src/tests/data/test_gpg.cfg"

    def test_load_from_config(self):
        config_file = utilities.load_config(self.config)
        (mykey, protocols, connectors, force_sender) = utilities.get_config_values(config_file)
        listeners, senders, monitors = utilities.configure_connectors(protocols, connectors)
        self.assertEqual('8888', listeners['https']['socket_port'])
        self.assertEqual('data/freedombuddy.crt', listeners['https']['ssl_certificate'])
        self.assertEqual('data/freedombuddy.crt', listeners['https']['ssl_private_key'])

if __name__ == "__main__":
    unittest.main()
