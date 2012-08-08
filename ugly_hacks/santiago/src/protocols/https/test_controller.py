"""Tests for the HTTPS controller."""

import cherrypy
import ConfigParser as configparser
import httplib, urllib
import json
import sys
import time
import unittest

import protocols.https.controller as controller
import santiago
import utilities


class CherryPyTester(unittest.TestCase):

    def test_right_version(self):
        """CherryPy < 3.2 hoses things silently."""

        self.assertTrue([int(x) for x in cherrypy.__version__.split(".")]
                        >= [3,2])

class RestTester(unittest.TestCase):

    if sys.version_info < (2, 7):
        """Add a poor man's forward compatibility."""

        class ContainsError(AssertionError):
            pass

        def assertIn(self, a, b):
            if not a in b:
                raise self.ContainsError("%s not in %s" % (a, b))

class MonitorTest(RestTester):
    """Generic test-class.

    This is, unfortunately, bad effect testing.  I'm depending on way too much
    code to get things set up and this should be broken out much more.  However,
    it's testable and, more than anything, I need to get this under test.

    """
    def setUp(self):
        """Create my FBuddy, start it, and make a connector to it."""

        super(MonitorTest, self).setUp()

        self.conn = httplib.HTTPSConnection("localhost", 8080)

        # import pdb; pdb.set_trace()
        self.santiago = self.create_santiago()
        self.santiago.__enter__()

    def create_santiago(self):
        # get my key, if possible
        try:
            mykey = utilities.load_config("../data/test.cfg").get(
                "pgpprocessor", "keyid")
        except configparser.NoSectionError:
            mykey = 0

        # set up monitors, listeners, and senders
        cert = "../data/freedombuddy.crt"
        protocol = "https"
        service = "freedombuddy"
        location = "https://localhost:"
        serving_port = 8080

        listeners = { protocol: { "socket_port": serving_port,
                                 "ssl_certificate": cert,
                                 "ssl_private_key": cert
                                  }, }
        senders = { protocol: { "proxy_host": "localhost",
                               "proxy_port": 8118} }
        monitors = { protocol: {} }

        # services to host and consume
        hosting = { mykey: { service: [location + str(serving_port)] } }
        consuming = { mykey: { service: [location + str(serving_port)] } }

        # go!
        return santiago.Santiago(listeners, senders,
                                 hosting, consuming,
                                 me=mykey, monitors=monitors)

    def tearDown(self):
        self.santiago.live = 0
        self.santiago.__exit__(None, 0, None)

    def get_args(self, *args, **kwargs):
        """Record arguments."""

        self.args = args
        self.kwargs = kwargs

class HttpMonitorTest(unittest.TestCase):
    def setUp(self):
        self.monitor = controller.HttpMonitor(None)

class HttpMonitorQueryTest(HttpMonitorTest):
    """Test HttpMonitor's Queries."""

    def test_full_urls(self):
        url = "https://localhost:8080/index?something=somethingelse"
        self.assertEqual( { "something": "somethingelse" },
                          self.monitor._parse_query(url) )

    def test_query_strings(self):
        url = "something=somethingelse"
        self.assertEqual( { "something": "somethingelse" },
                          self.monitor._parse_query(url) )

    def test_with_question(self):
        url = "?something=somethingelse"
        self.assertEqual( { "something": "somethingelse" },
                          self.monitor._parse_query(url) )

    def test_multiple_url_queries(self):
        url = "https://localhost:8080/index?something=somethingelse&this=that&1=2"
        self.assertEqual( { "something": "somethingelse",
                            "this": "that",
                            "1": "2" },
                          self.monitor._parse_query(url) )

    def test_multiple_string_queries(self):
        url = "?something=somethingelse&this=that&1=2"
        self.assertEqual( { "something": "somethingelse",
                            "this": "that",
                            "1": "2" },
                          self.monitor._parse_query(url) )

class HttpMonitorRespondTest(HttpMonitorTest):
    """Nothing I can think of testing here.

    It's really just verifying Cheetah's Templates.  Worthwhile, perhaps?
    Still, not a high priority.

    """
    pass

class StopTest(MonitorTest):
    def test_post(self):
        controller.query(self.conn, url="/stop")

        self.assertFalse(self.santiago.live)

class Learn(MonitorTest):

    def setUp(self):
        super(Learn, self).setUp()

        self.service = "atest"
        self.value = 3

        self.santiago.create_hosting_location(self.santiago.me, self.service,
                                              [self.value])

    # def test_post(self):
    #     """Make sure arguments are actually passed to the Santiago as expected.

    #     """
    #     self.santiago.query = self.args

    #     raise NotImplemented("ohnoes!")

    def test_learn_hosted_services(self):
        """Make sure requests to learners actually result in learned services.

        """
        controller.query(self.conn, "learn", self.santiago.me, self.service,
                         action="POST")

        self.assertEqual(
            self.santiago.get_client_locations(self.santiago.me, self.service),
            self.value)

    def test_redirected_to_service(self):
        """The HTTPS controller redirects to the learned service's location."""

        data = controller.query(self.conn, "learn", self.santiago.me,
                                self.service, action="POST")

        self.assertIn("""\
This resource can be found at <a href='https://{0}:{1}/consuming/{2}/{3}'>\
""".format(self.conn.host, self.conn.port, self.santiago.me, self.service),
                      data)

class Listener(MonitorTest):
    """External incoming-request listener.

    All HTTPS requests and replies eventually funnel into here, so if this won't
    work, nothing will.

    """
    def setUp(self):
        """Create a FreedomBuddy that knows about itself."""

        super(Listener, self).setUp()

        self.service = "atest"
        self.value = 3

        self.santiago.create_hosting_location(self.santiago.me, self.service,
                                              [self.value])

        self.request = {
            "request":
                self.santiago.gpg.encrypt(
                json.dumps({ "host": self.santiago.me,
                             "client": self.santiago.me,
                             "service": self.service,
                             "locations": [self.value],
                             "reply_to": [],
                             "request_version": 1,
                             "reply_versions":
                                 list(santiago.Santiago.SUPPORTED_PROTOCOLS),}),

            self.santiago.me,
            sign=self.santiago.me)}

    def test_learn_hosted_services(self):
        """Make sure requests to listeners actually result in learned services.

        FIXME: or rather, fix controller::Listener::index.  I shouldn't be able
        to GET here.

        """
        controller.query(self.conn, "/", params=self.request)

        time.sleep(1)

        self.assertEqual(
            self.santiago.get_client_locations(self.santiago.me, self.service),
            self.value)

    def test_learn_hosted_services_the_right_way(self):
        """Make sure requests to listeners actually result in learned services.

        """
        controller.query(self.conn, "/", action="POST", body=self.request)

        time.sleep(1)

        self.assertEqual(
            self.santiago.get_client_locations(self.santiago.me, self.service),
            self.value)

    def test_catch_outgoing_request(self):
        """If I make an outgoing request, does the listener hear it?"""

        self.santiago.listeners["https"].incoming_request = self.get_args

        id = self.santiago.me
        self.santiago.outgoing_request(id, id, id, id, self.service)

        self.assertTrue(self.kwargs["request"])



if __name__ == "__main__":
    unittest.main()
