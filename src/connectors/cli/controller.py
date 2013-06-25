#! /usr/bin/env python
# -*- mode: python; mode: auto-fill; fill-column: 80; -*-

from twisted.internet import protocol, reactor
import src.santiago as santiago
import json

class CliListener(santiago.SantiagoListener, protocol.Protocol):
    def __init__(self, *args, **kwargs):
        super(CliListener, self).__init__(*args, **kwargs)
        self.listener = self.load_connector("listeners")
        self.sender = self.load_connector("senders")
        self.querier = santiago.Query(self.santiago)

    def start(self, port):
        factory = CliListenerFactory()
        reactor.listenTCP(port, factory)
        reactor.run()

    def stop(self):
        santiago.Stop(self.santiago).post()
        reactor.stop()

    def incoming_request(self, *args, **kwargs):
        return self.listener.incoming_request(*args, **kwargs)

    def outgoing_request(self, *args, **kwargs):
        return self.sender.outgoing_request(*args, **kwargs)

    def query(self, *args, **kwargs):
        return self.querier.post(*args, **kwargs)

    def hosting(self, operation, client, service=None, location=None, update=None):
        """Update a service I am hosting for other clients."""

        return self._change(operation, True, client, service, location, update)

    def consuming(self, operation, host, service=None, location=None, update=None):
        """Update a service I consume from other hosts."""

        return self._change(operation, False, host, service, location, update)

    def _change(self, operation, i_host, key, service=None, location=None, update=None):
        """Change Santiago's known clients, servers, services, and locations."""

        if operation == "add":
            action = "put"
        elif operation == "remove":
            action = "delete"
        elif operation == "list":
            action = "get"
        else:
            action = "get"

        # if we're modifying data
        if action != "get":
            if location != None:
                actor = santiago.HostedService if i_host else santiago.ConsumedService
            elif service != None:
                actor = santiago.HostedClient if i_host else santiago.ConsumedHost
            elif key != None:
                actor = santiago.Hosting if i_host else santiago.Consuming
            else:
                actor = None
        # just listing data, don't need to handle listing indvidiual locations.
        elif action == "get":
            if service != None:
                actor = santiago.HostedService if i_host else santiago.ConsumedService
            elif key != None:
                actor = santiago.HostedClient if i_host else santiago.ConsumedHost
            else:
                actor = santiago.Hosting if i_host else santiago.Consuming

        # for the day that I change things up and completely forget to update
        # this line.
        else:
            raise RuntimeError("Invalid Action.")

        # think:
        #     x = santiago.ConsumedService(SANTIAGO_INSTANCE)
        #     x.GET(key, service, location)
        return json.dumps(getattr(actor(self.santiago), action)(key,
                                                  service=service,
                                                  location=location,
                                                  update = update))


    def load_connector(self, attr):
        """Load the cli-specific connector from the Santiago Instance.

        Ignore KeyErrors, if they occur: in these cases, the user didn't want to
        use optional functionality.

        """
        try:
            return getattr(self.santiago, attr)
        except KeyError:
            pass

class CliListenerFactory(protocol.ServerFactory):
    protocol = CliListener

class CliMonitor(santiago.SantiagoListener, protocol.Protocol):

    def __init__(self, *args, **kwargs):
        super(CliMonitor, self).__init__(*args, **kwargs)

    def start(self, port):
        factory = CliMonitorFactory()
        reactor.listenTCP(port, factory)
        reactor.run()

    def stop(self):
        santiago.Stop(self.santiago).post()
        reactor.stop()

class CliMonitorFactory(protocol.ServerFactory):
    protocol = CliMonitor

class CliSender(santiago.SantiagoListener, protocol.Protocol):

    def __init__(self, https_sender = None, cli_sender = None, *args, **kwargs):
        super(CliSender, self).__init__(*args, **kwargs)
        self.senders = {"https": https_sender, "cli": cli_sender}

    def start(self, port):
        factory = CliSenderFactory()
        reactor.listenTCP(port, factory)
        reactor.run()

    def stop(self):
        santiago.Stop(self.santiago).post()
        reactor.stop()

    def outgoing_request(self, request, destination):
        """Send a request out through the command line interface.

        Don't queue, just immediately send the reply to each location we know.

        """
        protocol = destination.split(":")[0]

        code = self.senders[protocol]
        code = code.replace("$DESTINATION", pipes.quote(str(destination)))
        code = code.replace("$REQUEST", pipes.quote(str(request)))

        subprocess.call(code)

class CliSenderFactory(protocol.ServerFactory):
    protocol = CliSender
