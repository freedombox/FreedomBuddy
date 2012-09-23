"""The HTTPS Santiago listener and sender.

FIXME: add real authentication.

"""

import santiago

from Cheetah.Template import Template
import cherrypy
import httplib2, socks
import urllib, urlparse
import sys
import logging


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


class Listener(santiago.SantiagoListener):

    def __init__(self, my_santiago, socket_port=0,
                 ssl_certificate="", ssl_private_key="", **kwargs):

        santiago.debug_log("Creating Listener.")

        super(santiago.SantiagoListener, self).__init__(my_santiago, **kwargs)

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

            self.incoming_request(kwargs["request"])
        except Exception as e:
            logging.exception(e)

class Sender(santiago.SantiagoSender):

    def __init__(self, my_santiago,
                 proxy_type = socks.PROXY_TYPE_SOCKS5,
                 proxy_host = "",
                 proxy_port = 0,
                 **kwargs):

        super(santiago.SantiagoSender, self).__init__(my_santiago, **kwargs)

        self.proxy = None

        # FIXME Fix proxying.  There's bitrot or version skew here.
        proxytest = 1
        if proxytest == 1:
            self.proxy = httplib2.ProxyInfo(proxy_type, proxy_host, int(proxy_port))
        else if proxytest == 2:
            self.proxy = socks.socksocket()
            self.proxy.setproxy(proxy_type, proxy_host, int(proxy_port))

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

class Monitor(santiago.SantiagoMonitor):

    def __init__(self, aSantiago, **kwargs):
        santiago.debug_log("Creating Monitor.")

        super(Monitor, self).__init__(aSantiago, **kwargs)

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
            ('/learn/:host/:service', HttpLearn(self.santiago)),
            ("/stop", HttpStop(self.santiago)),
            ("/freedombuddy", root),
            )

        for location, handler in routing_pairs:
            Monitor.rest_connect(d, location, handler)

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

class HttpMonitor(object):

    # FIXME filter input and escape output properly.
    # FIXME This input shows evidence of vulnerability: <SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>
    # FIXME build tests for this.
    # FIXME change page headers based on encoding.

    # http://ha.ckers.org/xss.html

    def __init__(self, *args, **kwargs):
        super(HttpMonitor, self).__init__()
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

        return [str(Template(
                    file="/".join((self.relative_path, encoding,
                                   self.santiago.locale, template)),
                    searchList = [dict(values)]))]

class HttpRoot(santiago.SantiagoMonitor, HttpMonitor):
    @cherrypy.tools.ip_filter()
    def GET(self, **kwargs):
        return self.respond("root.tmpl", {})

class HttpStop(santiago.Stop, HttpMonitor):
    @cherrypy.tools.ip_filter()
    def POST(self, **kwargs):
        super(HttpStop, self).POST(**kwargs)
        raise cherrypy.HTTPRedirect("/")

class HttpLearn(santiago.Learn, HttpMonitor):
    @cherrypy.tools.ip_filter()
    def POST(self, host, service):
        super(HttpLearn, self).POST(host, service)
        raise cherrypy.HTTPRedirect("/consuming/%s/%s" % (host, service))

class HttpHosting(santiago.Hosting, HttpMonitor):
    @cherrypy.tools.ip_filter()
    def GET(self, **kwargs):
        return self.respond("hosting.tmpl",
                            super(HttpHosting, self).GET(**kwargs),
                            **kwargs)

    @cherrypy.tools.ip_filter()
    def POST(self, put="", delete="", **kwargs):
        if put:
            self.PUT(put)
        elif delete:
            self.DELETE(delete)

    @cherrypy.tools.ip_filter()
    def PUT(self, client, **kwargs):
        super(HttpHosting, self).PUT(client)

    @cherrypy.tools.ip_filter()
    def DELETE(self, client):
        super(HttpHosting, self).DELETE(client)

class HttpHostedClient(santiago.HostedClient, HttpMonitor):

    # FIXME correct direct key access
    @cherrypy.tools.ip_filter()
    def GET(self, client, **kwargs):
        return self.respond("hostedClient.tmpl",
                            super(HttpHostedClient, self).GET(client, **kwargs),
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
        super(HttpHostedClient, self).PUT(client, service)

    @cherrypy.tools.ip_filter()
    def DELETE(self, client, service):
        super(HttpHostedClient, self).DELETE(client, service)

class HttpHostedService(santiago.HostedService, HttpMonitor):
    @cherrypy.tools.ip_filter()
    def GET(self, client, service, **kwargs):
        return self.respond(
            "hostedService.tmpl",
            super(HttpHostedService, self).GET(client, service, **kwargs),
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
        super(HttpHostedService, self).PUT(client, service, location, **kwargs)

    @cherrypy.tools.ip_filter()
    def DELETE(self, client, service, location, **kwargs):
        super(HttpHostedService, self).DELETE(client, service, location,
                                              **kwargs)

class HttpConsuming(santiago.Consuming, HttpMonitor):
    @cherrypy.tools.ip_filter()
    def GET(self, **kwargs):
        return self.respond("consuming.tmpl",
                            super(HttpConsuming, self).GET(**kwargs),
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
        super(HttpConsuming, self).PUT(host, **kwargs)

    @cherrypy.tools.ip_filter()
    def DELETE(self, host, **kwargs):
        super(HttpConsuming, self).DELETE(host, **kwargs)

class HttpConsumedHost(santiago.ConsumedHost, HttpMonitor):
    @cherrypy.tools.ip_filter()
    def GET(self, host, **kwargs):
        return self.respond(
            "consumedHost.tmpl",
            super(HttpConsumedHost, self).GET(host, **kwargs),
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
        super(HttpConsumedHost, self).PUT(host, service, **kwargs)

    @cherrypy.tools.ip_filter()
    def DELETE(self, host, service, **kwargs):
        super(HttpConsumedHost, self).DELETE(host, service, **kwargs)

class HttpConsumedService(santiago.ConsumedService, HttpMonitor):
    @cherrypy.tools.ip_filter()
    def GET(self, host, service, **kwargs):
        return self.respond(
            "consumedService.tmpl",
            super(HttpConsumedService, self).GET(host, service, **kwargs),
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
        super(HttpConsumedService, self).PUT(host, service, location, **kwargs)

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
