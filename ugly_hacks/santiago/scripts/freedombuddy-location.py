#! /usr/bin/python

"""Prints FreedomBuddy locations to screen.

This script is designed to show where a buddy is providing a service.  It
accepts a key that identifies a trusted party and the service to show locations
for.  It can show where someone else is hosting a service for me and it can show
where I am hosting a service for a client.  It will print one location per line.

Parameters
==========

* --key

    The key to query for.

* --service

    The service to query for.
* --timeout=60s

    Maximum time to wait for the request to finish, before reporting known
    (locally cached) locations.

* --(host|client)

    Only one of these may be used at a time.

    :host: Query the named key's FreedomBuddy service for the named service's
        location.  Yes, a service-providing-service results in redundant
        sentences like that one.

    :client: Query my FreedomBuddy service for locations I'm hosting the service
        for the client.

* --(no-query|force-query)

    Only one of these may be used at a time.

    :force-query: Reserved for future use.  If we add timeouts to prevent too
        frequent querying (e.x., each service's query is valid for X minutes),
        force-query can be used to override the timeout and force a request.

    :no-query: Don't query on the FreedomBuddy service, whether or not the
        previous request has timed out.  Use the locally cached services only.
        The ``--client`` parameter implies this option.

"""
