"""Tests for the CLI controller."""

import src.connectors.cli.controller as controller
import unittest
import gnupg
import src.utilities as utilities
import src.santiago as santiago
import logging
from datetime import datetime
import time
from time import sleep

class CliListener(unittest.TestCase):
    """Test main code call."""
    def setUp(self):
        self.gpg = gnupg.GPG(homedir='src/tests/data/test_gpg_home')
        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")
        self.test_keyid = "1111111111111111111111111111111111111111"
        self.original_update_time = time.time()

        self.santiago = santiago.Santiago(
            hosting = {self.keyid: {santiago.Santiago.SERVICE_NAME: ["http://127.0.0.1"], santiago.Santiago.SERVICE_NAME+'-update-timestamp': str(self.original_update_time) }},
            consuming = {self.keyid: {santiago.Santiago.SERVICE_NAME: ["http://127.0.0.2"], santiago.Santiago.SERVICE_NAME+'-update-timestamp': str(self.original_update_time) }},
            my_key_id = self.keyid,
            gpg = self.gpg,
            save_dir='src/tests/data/CLI_Controller')
        self.cliListener = controller.CliListener(santiago_to_use = self.santiago)
        #self.cliListener.start(8001)

    def test_get_hosting_clients(self):
        """Confirm hosting clients are returned correctly."""
        self.assertEqual('{"clients": ["'+self.keyid+'"]}', self.cliListener.hosting("list", None))

    def test_get_hosting_services(self):
        """Confirm services we host for client are returned correctly."""
        self.assertEqual('{"services": {"freedombuddy": ["http://127.0.0.1"], "freedombuddy-update-timestamp": "'+str(self.original_update_time)+'"}, "client": "'+self.keyid+'"}', self.cliListener.hosting("list", self.keyid))

    def test_get_hosting_service_locations(self):
        """Confirm locations we host for client x service are returned correctly."""
        self.assertEqual('{"client": "'+self.keyid+'", "locations": ["http://127.0.0.1"], "service": "freedombuddy"}', self.cliListener.hosting("list", self.keyid, "freedombuddy"))

    def test_get_consuming_clients(self):
        """Confirm consuming hosts are returned correctly."""
        self.assertEqual('{"hosts": ["'+self.keyid+'"]}', self.cliListener.consuming("list", None))

    def test_get_consuming_services(self):
        """Confirm services we consume from host are returned correctly."""
        self.assertEqual('{"services": {"freedombuddy": ["http://127.0.0.2"], "freedombuddy-update-timestamp": "'+str(self.original_update_time)+'"}, "host": "'+self.keyid+'"}', self.cliListener.consuming("list", self.keyid))

    def test_get_consuming_service_locations(self):
        """Confirm locations we consume from host x service are returned correctly."""
        self.assertEqual('{"host": "'+self.keyid+'", "locations": ["http://127.0.0.2"], "service": "freedombuddy"}', self.cliListener.consuming("list", self.keyid, "freedombuddy"))

    def test_add_hosting_client(self):
        """Confirm client is added to hosting list."""
        self.cliListener.hosting("add", self.test_keyid)
        self.assertEqual('{"clients": ["'+self.test_keyid+'", "'+self.keyid+'"]}', self.cliListener.hosting("list", None))

    def test_add_hosting_client_service(self):
        """Confirm service is added for client."""
        sleep(2)
        time_to_use = str(self.original_update_time+1)
        self.cliListener.hosting("add", self.test_keyid, "freedombuddy", update = time_to_use)
        self.assertEqual('{"services": {"freedombuddy": [], "freedombuddy-update-timestamp": "'+time_to_use+'"}, "client": "'+self.test_keyid+'"}', self.cliListener.hosting("list", self.test_keyid))

    def test_add_hosting_service_locations(self):
        """Confirm location is added for service x client."""
        sleep(2)
        time_to_use = str(self.original_update_time+1)
        self.cliListener.hosting("add", self.test_keyid, "freedombuddy", "http://127.0.0.1", time_to_use)
        self.assertEqual('{"client": "'+self.test_keyid+'", "locations": ["http://127.0.0.1"], "service": "freedombuddy"}', self.cliListener.hosting("list", self.test_keyid, "freedombuddy"))
        self.assertEqual('{"client": "'+self.test_keyid+'", "locations": "'+time_to_use+'", "service": "freedombuddy-update-timestamp"}', self.cliListener.hosting("list", self.test_keyid, "freedombuddy-update-timestamp"))

    def test_add_consuming_client(self):
        """Confirm client is added to consuming list."""
        self.cliListener.consuming("add", self.test_keyid)
        self.assertEqual('{"hosts": ["'+self.test_keyid+'", "'+self.keyid+'"]}', self.cliListener.consuming("list", None))

    def test_add_consuming_client_service(self):
        """Confirm service is added for client."""
        sleep(2)
        time_to_use = str(self.original_update_time+1)
        self.cliListener.consuming("add", self.test_keyid, "freedombuddy", update = time_to_use)
        self.assertEqual('{"services": {"freedombuddy": [], "freedombuddy-update-timestamp": "'+time_to_use+'"}, "host": "'+self.test_keyid+'"}', self.cliListener.consuming("list", self.test_keyid))

    def test_add_consuming_service_locations(self):
        """Confirm location is added for service x client."""
        sleep(2)
        time_to_use = str(self.original_update_time+1)
        self.cliListener.consuming("add", self.test_keyid, "freedombuddy", "http://127.0.0.1", time_to_use)
        self.assertEqual('{"host": "'+self.test_keyid+'", "locations": ["http://127.0.0.1"], "service": "freedombuddy"}', self.cliListener.consuming("list", self.test_keyid, "freedombuddy"))
        self.assertEqual('{"host": "'+self.test_keyid+'", "locations": "'+time_to_use+'", "service": "freedombuddy-update-timestamp"}', self.cliListener.consuming("list", self.test_keyid, "freedombuddy-update-timestamp"))

    def test_remove_hosting_client(self):
        """Confirm client is removed."""
        self.cliListener.hosting("remove", self.keyid)
        self.assertEqual('{"clients": []}', self.cliListener.hosting("list", None))

    def test_remove_hosting_service(self):
        """Confirm client is removed."""
        self.cliListener.hosting("remove", self.keyid, "freedombuddy")
        self.assertEqual('{"services": {}, "client": "'+self.keyid+'"}', self.cliListener.hosting("list", self.keyid))

    def test_remove_hosting_location(self):
        """Confirm client is removed."""
        self.cliListener.hosting("remove", self.keyid, "freedombuddy", "http://127.0.0.1")
        self.assertEqual('{"services": {"freedombuddy": [], "freedombuddy-update-timestamp": "'+str(self.original_update_time)+'"}, "client": "'+self.keyid+'"}', self.cliListener.hosting("list", self.keyid))

    def test_remove_consuming_client(self):
        """Confirm client is removed."""
        self.cliListener.consuming("remove", self.keyid)
        self.assertEqual('{"hosts": []}', self.cliListener.consuming("list", None))

    def test_remove_consuming_service(self):
        """Confirm service is removed."""
        self.cliListener.consuming("remove", self.keyid, "freedombuddy")
        self.assertEqual('{"services": {}, "host": "'+self.keyid+'"}', self.cliListener.consuming("list", self.keyid))

    def test_remove_consuming_location(self):
        """Confirm location is removed."""
        self.cliListener.consuming("remove", self.keyid, "freedombuddy", "http://127.0.0.2")
        self.assertEqual('{"services": {"freedombuddy": [], "freedombuddy-update-timestamp": "'+str(self.original_update_time)+'"}, "host": "'+self.keyid+'"}', self.cliListener.consuming("list", self.keyid))

class CliSender(unittest.TestCase):
    """Test main code call."""
    def setUp(self):
        self.gpg = gnupg.GPG(homedir='src/tests/data/test_gpg_home')
        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")
        self.test_keyid = "1111111111111111111111111111111111111111"
        self.santiago = santiago.Santiago(
            hosting = {self.keyid: {santiago.Santiago.SERVICE_NAME: ["http://127.0.0.1"], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None }},
            consuming = {self.keyid: {santiago.Santiago.SERVICE_NAME: ["http://127.0.0.2"], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None }},
            my_key_id = self.keyid,
            gpg = self.gpg,
            save_dir='src/tests/data/CLI_Controller')
        self.cliSender = controller.CliSender(santiago_to_use = self.santiago, 
                                              https_sender = "python src/connectors/https/controller.py --outgoing $REQUEST --destination $DESTINATION",
                                              cli_sender = "echo $DESTINATION $REQUEST")

if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    unittest.main()
