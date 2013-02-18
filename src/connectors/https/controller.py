#! /usr/bin/env python
# -*- mode: python; mode: auto-fill; fill-column: 80; -*-

"""The HTTPS Santiago listener and sender.

FIXME: add real authentication.

"""

import ast
from Cheetah.Template import Template
import cherrypy
import httplib
import httplib2, socks
import json
from optparse import OptionParser
import os
import pipes
import shlex
import subprocess
import sys
import logging
import urllib, urlparse

import santiago


COMMAND_LINE = "python connectors/cli/controller.py"
def command(aCommand):
    """Pass the request to the command line client and unwrap the reply."""

    myCommand = shlex.split(COMMAND_LINE + " " + aCommand)
    x = subprocess.Popen(myCommand, stdout=subprocess.PIPE)
    stdout = x.communicate()[0]

    try:
        jsonstr = str(json.loads(stdout))
    except ValueError:
        return

    return ast.literal_eval(jsonstr)

def allow_ips(ips = None):
    """Refuse connections from non-whitelisted IPs.

    Defaults to the localhost.

    Hook documentation is available in:

    http://docs.cherrypy.org/dev/progguide/extending/customtools.html

    """
    if ips == None:
        ips = [ "127.0.0.1" ]

    if cherrypy.request.remote.ip not in ips:
        santiago.debug_log("Request from non-local IP.  Forbidden.")
        raise cherrypy.HTTPError(403)

def allow_requests(requests = None):
    """Refuse non-whitelisted request types.

    Defaults to "GET"

    """
    if requests is None:
        requests = [ "GET" ]

    # just in case they entered a single allowed type, like "POST"
    if not hasattr(requests, "__iter__"):
        requests = [requests]

    if cherrypy.request.method not in requests:
        santiago.debug_log("Request of improper type.  Forbidden.")
        raise cherrypy.HTTPError(405)

cherrypy.tools.ip_filter = cherrypy.Tool('before_handler', allow_ips)
cherrypy.tools.request_filter = cherrypy.Tool('before_handler', allow_requests)


def start(*args, **kwargs):
    """Module-level start function, called after listener and sender started.

    """
    cherrypy.engine.start()

def stop(*args, **kwargs):
    """Module-level stop function, called after listener and sender stopped.

    """
    cherrypy.engine.stop()
    cherrypy.engine.exit()


class HttpsListener(santiago.SantiagoListener):

    def __init__(self, socket_port=0,
                 ssl_certificate="", ssl_private_key="",
                 *args, **kwargs):

        santiago.debug_log("Creating Listener.")

        super(HttpsListener, self).__init__(*args, **kwargs)

        cherrypy.server.socket_port = int(socket_port)
        cherrypy.server.ssl_certificate = ssl_certificate
        cherrypy.server.ssl_private_key = ssl_private_key

        d = cherrypy.dispatch.RoutesDispatcher()
        d.connect("index", "/", self.index)

        cherrypy.tree.mount(cherrypy.Application(self), "",
                            {"/": {"request.dispatch": d}})

        santiago.debug_log("Listener Created.")

    @cherrypy.tools.ip_filter()
    @cherrypy.tools.request_filter(requests = "POST")
    def index(self):
        """Receive an incoming Santiago request from another Santiago client."""

        try:
            body = cherrypy.request.body.read()
            santiago.debug_log("Received request {0}".format(str(body)))

            kwargs = urlparse.parse_qs(body)

            command("--request {0}".format(pipes.quote(kwargs["request"][0])))
        except Exception as e:
            logging.exception(e)

class HttpsSender(santiago.SantiagoSender):

    def __init__(self,
                 proxy_type = socks.PROXY_TYPE_SOCKS5,
                 proxy_host = "",
                 proxy_port = 0,
                 *args, **kwargs):

        super(HttpsSender, self).__init__(*args, **kwargs)

        self.proxy = None

        # FIXME Fix proxying.  There's bitrot or version skew here.
        if proxy_type and proxy_host and proxy_port:

            proxytest = 1

            if proxytest == 1:
                self.proxy = socks.socksocket()
                self.proxy.setproxy(proxy_type, proxy_host, int(proxy_port))
            else:
                self.proxy = httplib2.ProxyInfo(proxy_type, proxy_host,
                                                int(proxy_port))

    @cherrypy.tools.ip_filter()
    def outgoing_request(self, request, destination):
        """Send an HTTPS request to each Santiago client.

        Don't queue, just immediately send the reply to each location we know.

        It's both simple and as reliable as possible.

        ``request`` is literally the request's text.  It needs to be wrapped for
        transport across the protocol.

        """
        santiago.debug_log("request {0}".format(str(request)))

        body = urllib.urlencode({ "request": request })

        if self.proxy:
            destination = str(destination)
            connection = httplib2.Http(proxy_info = self.proxy)
            connection.request(destination, "POST", body)
        else:
            connection = httplib.HTTPSConnection(destination.split("//")[1])
            connection.request("POST", "/", body)
            connection.close()

class HttpsMonitor(santiago.SantiagoMonitor):

    def __init__(self, socket_port=0,
                 ssl_certificate="", ssl_private_key="",
                 *args, **kwargs):

        santiago.debug_log("Creating Monitor.")

        super(HttpsMonitor, self).__init__(*args, **kwargs)

        cherrypy.server.socket_port = int(socket_port)
        cherrypy.server.ssl_certificate = ssl_certificate
        cherrypy.server.ssl_private_key = ssl_private_key

        try:
            d = cherrypy.tree.apps[""].config["/"]["request.dispatch"]
        except KeyError:
            d = cherrypy.dispatch.RoutesDispatcher()

        root = HttpRoot(self.santiago)

        routing_pairs = (
            ('/hosting/:client/:service', HttpHostedService(self.santiago)),
            ('/hosting/:client', HttpHostedClient(self.santiago)),
            ('/hosting', HttpHosting(self.santiago)),
            ('/consuming/:host/:service', HttpConsumedService(self.santiago)),
            ('/consuming/:host', HttpConsumedHost(self.santiago)),
            ('/consuming', HttpConsuming(self.santiago)),
            ('/query/:host/:service', HttpQuery(self.santiago)),
            ("/stop", HttpStop(self.santiago)),
            ("/freedombuddy", root),
            )

        for location, handler in routing_pairs:
            HttpsMonitor.rest_connect(d, location, handler)

        cherrypy.tree.mount(root, "", {"/": {"request.dispatch": d}})

        santiago.debug_log("Monitor Created.")

    @classmethod
    def rest_connect(cls, dispatcher, location, controller, trailing_slash=True):
        """Simple REST connector for object/location mapping."""

        if trailing_slash:
            location = location.rstrip("/")
            location = [location, location + "/"]
        else:
            location = [location]

        for place in location:
            for a_method in ("PUT", "GET", "POST", "DELETE"):
                dispatcher.connect(controller.__class__.__name__ + a_method,
                                   place, controller=controller, action=a_method,
                                   conditions={ "method": [a_method] })

        return dispatcher

class MonitorUtilities(object):
    """Utilities for the HTTP monitors."""

    # FIXME filter input and escape output properly.
    # FIXME This input shows evidence of vulnerability: <SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>
    # FIXME build tests for this.
    # FIXME change page headers based on encoding.

    # http://ha.ckers.org/xss.html

    def __init__(self, *args, **kwargs):
        super(MonitorUtilities, self).__init__(*args, **kwargs)
        self.relative_path = "connectors/https/templates"

    def _parse_query(self, query_input):
        """Split a URL into its query string.

        Might raise any of: ValueError, TypeError, NameError

        """
        query = ""

        if query_input:
            query_input = query_input[query_input.find("?")+1:]
            query = dict([item.split("=") for item in query_input.split("&")])

        return query

    def respond(self, template, values, encoding="html"):
        try:
            query = self._parse_query(cherrypy.request.query_string)
        except (ValueError, TypeError, NameError):
            return

        if query:
            try:
                encoding = query["encoding"]
            except KeyError:
                pass

        try:
            mySearchList = [dict(values)]
        except TypeError:
            raise cherrypy.HTTPError(500, "No values.")
        # return page content only if no errors.
        return [str(Template(
                    file="/".join((self.relative_path, encoding,
                                   os.environ["LANG"].split("_")[0],
                                   template)),
                    searchList=mySearchList))]

class HttpRoot(santiago.SantiagoMonitor, MonitorUtilities):
    """Present the user with the basic actions:

    - Stop
    - Hosting
    - Consuming

    """
    @cherrypy.tools.ip_filter()
    def GET(self, **kwargs):
        return self.respond("root.tmpl", {})

class HttpStop(santiago.Stop, MonitorUtilities):
    """Stop the service."""

    @cherrypy.tools.ip_filter()
    def POST(self, **kwargs):
        command("--stop")
        raise cherrypy.HTTPRedirect("/freedombuddy")

class HttpQuery(santiago.Query, MonitorUtilities):
    """A local-only interface to start the outgoing request process.

    This service request is eventually sent out to the host.

    """
    @cherrypy.tools.ip_filter()
    def POST(self, host, service):
        command("--query --key {0} --service {1}".format(host, service))
        raise cherrypy.HTTPRedirect("/consuming/%s/%s" % (host, service))

class HttpHosting(santiago.Hosting, MonitorUtilities):
    """List clients I'm hosting services for."""

    @cherrypy.tools.ip_filter()
    def GET(self, **kwargs):

        return self.respond(
            "hosting.tmpl",
            command("--action list --hosting"),
            **kwargs)

    @cherrypy.tools.ip_filter()
    def POST(self, put="", delete="", **kwargs):
        if put:
            self.PUT(put)
        elif delete:
            self.DELETE(delete)

    @cherrypy.tools.ip_filter()
    def PUT(self, client, **kwargs):
        command("--action add --hosting --key {0}".format(client))

    @cherrypy.tools.ip_filter()
    def DELETE(self, client):
        command("--action remove --hosting --key {0}".format(client))

class HttpHostedClient(santiago.HostedClient, MonitorUtilities):
    """List the services I'm hosting for the client."""

    @cherrypy.tools.ip_filter()
    def GET(self, client, **kwargs):
        return self.respond(
            "hostedClient.tmpl",
            command("--action list --hosting --key {0}".format(client)),
            **kwargs)

    @cherrypy.tools.ip_filter()
    def POST(self, client="", put="", delete="", **kwargs):
        if put:
            self.PUT(client, put)
        elif delete:
            self.DELETE(client, delete)

        raise cherrypy.HTTPRedirect("/hosting/" + client)

    @cherrypy.tools.ip_filter()
    def PUT(self, client, service):
        command("--action add --hosting --key {0} --service {1}".format(
                client, service))

    @cherrypy.tools.ip_filter()
    def DELETE(self, client, service):
        command("--action remove --hosting --key {0} --service {1}".format(
                client, service))

class HttpHostedService(santiago.HostedService, MonitorUtilities):
    """List locations I'm hosting the service for the client."""

    @cherrypy.tools.ip_filter()
    def GET(self, client, service, **kwargs):
        return self.respond(
            "hostedService.tmpl",
            command("--action list --hosting --key {0} --service {1}".format(
                    client, service)),
            **kwargs)

    @cherrypy.tools.ip_filter()
    def POST(self, client="", service="", put="", delete="", **kwargs):
        if put:
            self.PUT(client, service, put)
        elif delete:
            self.DELETE(client, service, delete)

        raise cherrypy.HTTPRedirect("/hosting/{0}/{1}/".format(client, service))

    @cherrypy.tools.ip_filter()
    def PUT(self, client, service, location, **kwargs):
        command(("--action add --hosting --key {0} --service {1}" +
                 " --location {2}").format(client, service, location)),

    @cherrypy.tools.ip_filter()
    def DELETE(self, client, service, location, **kwargs):
        command(("--action remove --hosting --key {0} --service {1}" +
                 " --location {2}").format(client, service, location)),

class HttpConsuming(santiago.Consuming, MonitorUtilities):
    """Get the hosts I'm consuming services from."""

    @cherrypy.tools.ip_filter()
    def GET(self, **kwargs):
        return self.respond(
            "consuming.tmpl",
            command("--action list --consuming"),
            **kwargs)

    @cherrypy.tools.ip_filter()
    def POST(self, put="", delete="", **kwargs):
        if put:
            self.PUT(put)
        elif delete:
            self.DELETE(delete)

        raise cherrypy.HTTPRedirect("/consuming")

    @cherrypy.tools.ip_filter()
    def PUT(self, host, **kwargs):
        command("--action add --consuming --key {0}".format(host))

    @cherrypy.tools.ip_filter()
    def DELETE(self, host, **kwargs):
        command("--action remove --consuming --key {0}".format(host))

class HttpConsumedHost(santiago.ConsumedHost, MonitorUtilities):
    """Get the services I'm consuming from the host."""

    @cherrypy.tools.ip_filter()
    def GET(self, host, **kwargs):
        return self.respond(
            "consumedHost.tmpl",
            command("--action list --consuming --key {0}".format(host)),
            **kwargs)

    @cherrypy.tools.ip_filter()
    def POST(self, host="", put="", delete="", **kwargs):
        if put:
            self.PUT(host, put)
        elif delete:
            self.DELETE(host, delete)

        raise cherrypy.HTTPRedirect("/consuming/" + host)

    @cherrypy.tools.ip_filter()
    def PUT(self, host, service, **kwargs):
        command("--action add --consuming --key {0} --service {1}".format(
                host, service))

    @cherrypy.tools.ip_filter()
    def DELETE(self, host, service, **kwargs):
        command("--action remove --consuming --key {0} --service {1}".format(
                host, service))

class HttpConsumedService(santiago.ConsumedService, MonitorUtilities):
    """Get the locations of the service I'm consuming from the host."""

    @cherrypy.tools.ip_filter()
    def GET(self, host, service, **kwargs):
        return self.respond(
            "consumedService.tmpl",
            command("--action list --consuming --key {0} --service {1}".format(
                    host, service)),
            **kwargs)

    @cherrypy.tools.ip_filter()
    def POST(self, host="", service="", put="", delete="", **kwargs):
        if put:
            self.PUT(host, service, put)
        elif delete:
            self.DELETE(host, service, delete)

        raise cherrypy.HTTPRedirect("/consuming/{0}/{1}/".format(host, service))

    @cherrypy.tools.ip_filter()
    def PUT(self, host, service, location, **kwargs):
        command(("--action add --consuming --key {0} --service {1}" +
                 " --location {2}").format(host, service, location))

    @cherrypy.tools.ip_filter()
    def DELETE(self, host, service, location, **kwargs):
        super(HttpConsumedService, self).DELETE(host, service, location,
                                                **kwargs)

def query(conn, type="", id="", service="",
          action="GET", url="", params=None, body=None):
    """A helper method to request tests for the HTTPS controller.

    :conn: a httplib.HTTPSConnection.

    :type: the type of request (consuming, learning, hosting, stop, /).

    :id: the gpg key we're querying about

    :service: the service to request data for

    :action: GET, POST, PUT, DELETE (required when posting)

    :url: the url to query (required for weird controllers).  Defaults to
    ``/%(type)s/%(id)s/%(service)s?%(params)s``

    :params: the request parameters.  defaults to {}

    :body: the request's body.  ignored unless posting.

    """
    if params is None:
        params = {}
    params = urllib.urlencode(params)

    if action not in ("GET", "POST", "PUT", "DELETE"):
        return

    if action == "POST":
        if not body:
            body = urllib.urlencode({"host": id, "service": service})
        else:
            body = urllib.urlencode(body)

    if url:
        location = url % locals()
    else:
        location = "/{0}/{1}/{2}?{3}".format(type, id, service, params)

    conn.request(action, location, body)

    response = conn.getresponse()
    data = response.read()

    return data
