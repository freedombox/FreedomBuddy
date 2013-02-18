"""Tests for the HTTPS controller."""

import cherrypy
import connectors.https.controller as controller
import optparse
import sys
import unittest
import utilities

class CherryPyTester(unittest.TestCase):
    """Verify we're running the right CherryPy version.

    If not, we'll silently get all kinds of errors, without obvious cause.

    """
    def test_right_version(self):
        """CherryPy < 3.2 hoses things silently."""

        self.assertTrue([int(x) for x in cherrypy.__version__.split(".")]
                        >= [3,2])

class MonitorTest(unittest.TestCase):
    """Make testing controllers easier."""

    def command(self, aCommand):
        """Record arguments."""

        self.aCommand = aCommand

    def assertInCommand(self, commands):
        """Verify that all the commands are in the command line."""

        return map(self.assertInTuple, [(x, self.aCommand) for x in commands])

    def setUp(self):
        """Replace the actual command execution with our override."""

        controller.command = self.command

    if sys.version_info < (2, 7):
        # Add a poor man's forward compatibility.

        class ContainsError(AssertionError):
            pass

        def assertIn(self, a, b):
            if not a in b:
                raise self.ContainsError("%s not in %s" % (a, b))

        def assertInTuple(self, a_b):
            a, b = a_b
            return self.assertIn(a, b)

class Stopper(MonitorTest):
    """Test the "HttpStop" controller."""

    def test_stop_stops(self):
        """Stop must send the "--stop" command to the cli client."""

        try:
            controller.HttpStop().POST()
        except cherrypy.HTTPRedirect:
            pass

        self.assertEqual(self.aCommand, "--stop")

    def test_stop_redirects(self):
        """Stop redirects to ``/freedombuddy`` after POSTing."""

        self.assertRaises(cherrypy.HTTPRedirect,
                          controller.HttpStop().POST)

class Listener(MonitorTest):
    """Test the "HttpListener" controller."""

    def read_request(self, *args, **kwargs):
        return "request=aRequest"

    def test_listen_listens(self):
        """Listeners must send "--request" to the cli client."""

        fakefile = lambda: None
        fakefile.read = self.read_request

        cherrypy.request.body = fakefile
        controller.HttpsListener().index()
        cherrypy.request.body = None
        self.assertInCommand(["--request aRequest"])

class Hosting(MonitorTest):
    """Test the "HttpHosting" controller."""

    def setUp(self):
        super(Hosting, self).setUp()
        self.controller = controller.HttpHosting()
        self.controller.respond = lambda x,y: None

    def test_get(self):
        self.controller.GET()
        self.assertInCommand(("--action list", "--hosting"))

    def test_put(self):
        self.controller.PUT("a")
        self.assertInCommand(("--action add", "--hosting", "--key a"))

    def test_delete(self):
        self.controller.DELETE("a")
        self.assertInCommand(("--action remove", "--hosting", "--key a"))

class HostedClient(MonitorTest):
    """Test the "HttpHostedClient" controller."""

    def setUp(self):
        super(HostedClient, self).setUp()
        self.controller = controller.HttpHostedClient()
        self.controller.respond = lambda x,y: None

    def test_get(self):
        self.controller.GET("a")
        self.assertInCommand(("--action list", "--hosting", "--key a"))

    def test_put(self):
        self.controller.PUT("a", "b")
        self.assertInCommand(
            ("--action add", "--hosting", "--key a", "--service b"))

    def test_delete(self):
        self.controller.DELETE("a", "b")
        self.assertInCommand(
            ("--action remove", "--hosting", "--key a", "--service b"))

class HostedService(MonitorTest):
    """Test the "HttpHostedService" controller."""

    def setUp(self):
        super(HostedService, self).setUp()
        self.controller = controller.HttpHostedService()
        self.controller.respond = lambda x,y: None

    def test_get(self):
        self.controller.GET("a", "b")
        self.assertInCommand(
            ("--action list", "--hosting", "--key a", "--service b"))

    def test_put(self):
        self.controller.PUT("a", "b", "c")
        self.assertInCommand(
            ("--action add", "--hosting", "--key a", "--service b",
             "--location c"))

    def test_delete(self):
        self.controller.DELETE("a", "b", "c")
        self.assertInCommand(
            ("--action remove", "--hosting", "--key a", "--service b",
             "--location c"))

class Consuming(MonitorTest):
    """Test the "HttpConsuming" controller."""

    def setUp(self):
        super(Consuming, self).setUp()
        self.controller = controller.HttpConsuming()
        self.controller.respond = lambda x,y: None

    def test_get(self):
        self.controller.GET()
        self.assertInCommand(("--action list", "--consuming"))

    def test_put(self):
        self.controller.PUT("a")
        self.assertInCommand(("--action add", "--consuming", "--key a"))

    def test_delete(self):
        self.controller.DELETE("a")
        self.assertInCommand(("--action remove", "--consuming", "--key a"))

class ConsumedHost(MonitorTest):
    """Test the "HttpConsumedHost" controller."""

    def setUp(self):
        super(ConsumedHost, self).setUp()
        self.controller = controller.HttpConsumedHost()
        self.controller.respond = lambda x,y: None

    def test_get(self):
        self.controller.GET("a")
        self.assertInCommand(("--action list", "--consuming", "--key a"))

    def test_put(self):
        self.controller.PUT("a", "b")
        self.assertInCommand(
            ("--action add", "--consuming", "--key a", "--service b"))

    def test_delete(self):
        self.controller.DELETE("a", "b")
        self.assertInCommand(
            ("--action remove", "--consuming", "--key a", "--service b"))

class ConsumedService(MonitorTest):
    """Test the "HttpConsumedService" controller."""

    def setUp(self):
        super(ConsumedService, self).setUp()
        self.controller = controller.HttpConsumedService()
        self.controller.respond = lambda x,y: None

    def test_get(self):
        self.controller.GET("a", "b")
        self.assertInCommand(
            ("--action list", "--consuming", "--key a", "--service b"))

    def test_put(self):
        self.controller.PUT("a", "b", "c")
        self.assertInCommand(
            ("--action add", "--consuming", "--key a", "--service b",
             "--location c"))

    def test_delete(self):
        self.controller.DELETE("a", "b", "c")
        self.assertInCommand(
            ("--action remove", "--consuming", "--key a", "--service b",
             "--location c"))

class Query(MonitorTest):
    """Test the "HttpQuery" controller."""

    def setUp(self):
        super(Query, self).setUp()
        self.controller = controller.HttpQuery()

    def test_post(self):
        """Do requests hook into the CLI client?"""

        try:
            self.controller.POST("a", "b")
        except cherrypy.HTTPRedirect:
            pass
        self.assertInCommand(
            ("--query", "--key a", "--service b"))

    def test_post_redirects(self):
        """Are requests redirected appropriately?"""

        self.assertRaises(cherrypy.HTTPRedirect,
                          self.controller.POST, *("a", "b"))

if __name__ == "__main__":
    unittest.main()
