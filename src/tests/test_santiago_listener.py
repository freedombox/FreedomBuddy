#! /usr/bin/env python
# -*- mode: python; mode: auto-fill; fill-column: 80 -*-
"""Tests the ``SantiagoListener`` class."""
import santiago
import test_santiago

class ListenerTests(test_santiago.SantiagoTest):
    """Tests the ``SantiagoListener`` class.

    Mostly making sure entire requests are successfully passed down to the
    underlying Santiago.

    """
    def setUp(self):
        """Make sure an underlying Santiago correctly receives passed arguments.

        Create it, set its receiving methods to save off the arguments, and set
        a few values that we'll save off later.

        """
        self.listener = santiago.SantiagoListener(santiago.Santiago())

        self.listener.santiago.incoming_request = self.acall
        self.listener.santiago.get_client_locations = self.acall
        self.listener.santiago.query = self.acall
        self.listener.santiago.create_hosting_location = self.acall

        self.item_one, self.item_two, self.item_three = (1, 2, 3)

    def acall(self, *args, **kwargs):
        """Just record the passed through arguments."""

        self.args = args
        self.kwargs = kwargs

    def test_pass_incoming_request(self):
        self.listener.incoming_request(self.item_one)

        self.assertEqual(self.args, (self.item_one,))
