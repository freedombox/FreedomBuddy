#! /usr/bin/env python # -*- mode: python; mode: auto-fill; fill-column: 80; -*-

"""Automatically configure OpenVPN tunnels from a known host.

We do this by:

- Acquiring the host IP, the client IP, and the shared key from FBuddy.

- Comparing those to the existing values.

- If they've changed, update the values.

- If data's changed, restart the service.

:FIXME: add proxying.

This script assumes that the first entry in each data set is the only one we
need.  While each FBuddy key-value pair can have any number of elements, we
ignore all but the first.  The rest can be used for other exciting purposes.

"""

import httplib
import json
import optparse
import sys

import scripts.freedombuddy as freedombuddy


client_conf = """\
remote myremote.mydomain
dev tun
ifconfig {0} {1}
secret static.key
"""
vpn_dir = "/etc/openvpn"
client_conf_file = vpn_dir + "/client.conf"
server_conf_file = vpn_dir + "/server.conf"
key_file = vpn_dir + "/static.key"

def validate_args(args):
    """Interprets the passed in arguments."""

    parser = optparse.OptionParser()

    parser.add_option("-k", "--key", dest="key", help="""\
The OpenVPN host's key.
""")
    parser.add_option("-a", "--address", dest="address", default="localhost",
                      help="""\
The "local" FreedomBuddy address to query for services.

Doesn't necessarily have to be local, just has to be reachable and trusted.
""")
    parser.add_option("-p", "--port", dest="port", default=8080,
                      help="Localhost's FreedomBuddy port.")

    return parser.parse_args(args)

def write_if_changed(newData, afile):
    """Write new data to file if different than existing file contents."""

    changed = False
    oldData = None

    try:
        with open(afile) as infile:
            oldData = "\n".join([line.strip() for line in infile.readlines()])
    except IOError:
        # there was no file?
        changed = True

    if oldData != newData:
        try:
            with open(afile, "w") as outfile:
                outfile.write(newData)
                changed = True
        except IOError:
            # we didn't write new data?
            changed = False

    return changed


if __name__ == "__main__":

    restart = False

    # parse args
    (options, args) = validate_args(sys.argv)

    # get data from FBuddy
    extract = lambda x: json.loads(x)[0]
    request = lambda service: extract(
        freedombuddy.query_remotely(options.address, options.port,
                                    options.key, service,
                                    params={"encoding": "json"}))

    newHostIp = request("openvpn-host")
    newClientIp = request("openvpn-client")
    newKey = request("openvpn-key")

    # transform received data as necessary.
    newConfig = client_conf.format(newClientIp, newHostIp).strip()
    newKey = "\n".join(line.strip() for line in str(newKey).splitlines())

    # restart if data have changed
    restart = write_if_changed(newConfig, client_conf_file)
    restart = write_if_changed(newKey, key_file)

    if restart:
        subprocess.call("service openvpn restart".split())
