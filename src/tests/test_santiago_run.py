#! /usr/bin/env python # -*- mode: auto-fill; fill-column: 80 -*-

"""Tests for the Utilities functions.

These functions are mostly tested by testing completed on main Santiago functionality but these should be tested independantly as well.

"""

import unittest
import src.santiago_run as santiago_run

class ParseArgs(unittest.TestCase):
    """Validates arguments passed to command line
    """

    def test_default_values_returned_when_no_arguments_passed(self):
        (self.options, self.arguments) = santiago_run.parse_args([""])
        self.assertEqual(None, self.options.trace)
        self.assertEqual("data/production.cfg", self.options.config)
        self.assertEqual(None, self.options.verbose)
        self.assertEqual(None, self.options.default_services)
        self.assertEqual(None, self.options.forget_services)

    def test_values_returned_when_short_arguments_passed_in(self):
        (self.options, self.arguments) = santiago_run.parse_args(["-c","te","-v","-d","-f","-t"])
        self.assertEqual("te", self.options.config)
        self.assertEqual(1, self.options.verbose)
        self.assertEqual(1, self.options.trace)
        self.assertEqual(1, self.options.default_services)
        self.assertEqual(1, self.options.forget_services)