#! /usr/bin/env python # -*- mode: auto-fill; fill-column: 80 -*-

"""Tests for the Utilities functions.

These functions are mostly tested by testing completed on main Santiago functionality but these should be tested independantly as well.

"""

import unittest
import utilities
import gnupg
from ConfigParser import NoSectionError
from utilities import GPGNotSpecifiedError
from utilities import GPGKeyNotSpecifiedError

"""Need to test get_config_values / configure_connectors / multi_sign"""


class LoadConfig(unittest.TestCase):
    """Reads in correct data from config file.
    """

    def setUp(self):
        self.config_to_use = 'data/test_gpg.cfg'

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
        self.config_to_use = 'data/test_gpg.cfg'

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

class ParseArgs(unittest.TestCase):
    """Validates arguments passed to command line
    """

    def test_default_values_returned_when_no_arguments_passed(self):
        (self.options, self.arguments) = utilities.parse_args([""])
        self.assertEqual(None, self.options.trace)
        self.assertEqual("data/production.cfg", self.options.config)
        self.assertEqual(None, self.options.verbose)
        self.assertEqual(None, self.options.default_services)
        self.assertEqual(None, self.options.forget_services)

    def test_values_returned_when_short_arguments_passed_in(self):
        (self.options, self.arguments) = utilities.parse_args(["-c","te","-v","-d","-f","-t"])
        self.assertEqual("te", self.options.config)
        self.assertEqual(1, self.options.verbose)
        self.assertEqual(1, self.options.trace)
        self.assertEqual(1, self.options.default_services)
        self.assertEqual(1, self.options.forget_services)

class MultiSign(unittest.TestCase):
    """Helper function to sign a message a number of times with a certain key"""

    def setUp(self):
        self.gpg = gnupg.GPG(gnupghome='data/test_gpg_home')

    def test_incorrect_gpg_raises_error(self):
        self.assertRaises(GPGNotSpecifiedError, utilities.multi_sign, message="Test Message", gpg=None, keyid="1")

    def test_incorrect_gpg_key_raises_error(self):
        self.assertRaises(GPGKeyNotSpecifiedError, utilities.multi_sign, message="Test Message", gpg=self.gpg, keyid=None)

if __name__ == "__main__":
    unittest.main()
