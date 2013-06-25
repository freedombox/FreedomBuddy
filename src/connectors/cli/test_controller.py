"""Tests for the CLI controller."""

import src.connectors.cli.controller as controller
import unittest
import gnupg
import src.utilities as utilities
import src.santiago as santiago
import logging
from datetime import datetime

class Main(unittest.TestCase):
    """Test main code call."""
    def setUp(self):
        self.gpg = gnupg.GPG(gnupghome='src/tests/data/test_gpg_home')
        self.keyid = utilities.load_config("src/tests/data/test_gpg.cfg").get("pgpprocessor", "keyid")

        self.santiago = santiago.Santiago(
            hosting = {self.keyid: {santiago.Santiago.SERVICE_NAME: ["http://127.0.0.1"], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None }},
            consuming = {self.keyid: {santiago.Santiago.SERVICE_NAME: ["http://127.0.0.2"], santiago.Santiago.SERVICE_NAME+'-update-timestamp': None }},
            my_key_id = self.keyid,
            gpg = self.gpg,
            save_dir='src/tests/data/CLI_Controller')
        self.cli = controller.CliListener(santiago_to_use = self.santiago)
        #self.cli.start(8001)

    def test_get_hosting_clients(self):
        """Confirm hosting clients are returned correctly."""
        self.assertEqual('{"clients": ["95801F1ABE01C28B05ADBE5FA7C860604DAE2628"]}', self.cli.hosting("list", None))

    def test_get_hosting_services(self):
        """Confirm services we host for client are returned correctly."""
        self.assertEqual('{"services": {"freedombuddy": ["http://127.0.0.1"], "freedombuddy-update-timestamp": null}, "client": "95801F1ABE01C28B05ADBE5FA7C860604DAE2628"}', self.cli.hosting("list", "95801F1ABE01C28B05ADBE5FA7C860604DAE2628"))

    def test_get_hosting_service_locations(self):
        """Confirm locations we host for client x service are returned correctly."""
        self.assertEqual('{"client": "95801F1ABE01C28B05ADBE5FA7C860604DAE2628", "locations": ["http://127.0.0.1"], "service": "freedombuddy"}', self.cli.hosting("list", "95801F1ABE01C28B05ADBE5FA7C860604DAE2628", "freedombuddy"))

    def test_get_consuming_clients(self):
        """Confirm consuming hosts are returned correctly."""
        self.assertEqual('{"hosts": ["95801F1ABE01C28B05ADBE5FA7C860604DAE2628"]}', self.cli.consuming("list", None))

    def test_get_consuming_services(self):
        """Confirm services we consume from host are returned correctly."""
        self.assertEqual('{"services": {"freedombuddy": ["http://127.0.0.2"], "freedombuddy-update-timestamp": null}, "host": "95801F1ABE01C28B05ADBE5FA7C860604DAE2628"}', self.cli.consuming("list", "95801F1ABE01C28B05ADBE5FA7C860604DAE2628"))

    def test_get_consuming_service_locations(self):
        """Confirm locations we consume from host x service are returned correctly."""
        self.assertEqual('{"host": "95801F1ABE01C28B05ADBE5FA7C860604DAE2628", "locations": ["http://127.0.0.2"], "service": "freedombuddy"}', self.cli.consuming("list", "95801F1ABE01C28B05ADBE5FA7C860604DAE2628", "freedombuddy"))

    def test_add_hosting_client(self):
        """Confirm client is added to hosting list."""
        self.assertEqual('{"clients": ["95801F1ABE01C28B05ADBE5FA7C860604DAE2628"]}', self.cli.hosting("list", None))
        self.cli.hosting("add", "1111111111111111111111111111111111111111")
        self.assertEqual('{"clients": ["1111111111111111111111111111111111111111", "95801F1ABE01C28B05ADBE5FA7C860604DAE2628"]}', self.cli.hosting("list", None))

    def test_add_hosting_client_service(self):
        """Confirm service is added for client x host."""
        self.assertEqual('{"services": null, "client": "1111111111111111111111111111111111111111"}', self.cli.hosting("list", "1111111111111111111111111111111111111111"))
        self.cli.hosting("add", "1111111111111111111111111111111111111111", "freedombuddy")
        self.assertEqual('{"services": {"freedombuddy": [], "freedombuddy-update-timestamp": null}, "client": "1111111111111111111111111111111111111111"}', self.cli.hosting("list", "1111111111111111111111111111111111111111"))

    def test_add_hosting_service_locations(self):
        """Confirm location is added for service x client x host."""
        self.assertEqual('{"client": "1111111111111111111111111111111111111111", "locations": null, "service": "freedombuddy"}', self.cli.hosting("list", "1111111111111111111111111111111111111111", "freedombuddy"))
        date_to_use = str(datetime.utcnow())
        self.cli.hosting("add", "1111111111111111111111111111111111111111", "freedombuddy", "http://127.0.0.1", date_to_use)
        self.assertEqual('{"client": "1111111111111111111111111111111111111111", "locations": ["http://127.0.0.1"], "service": "freedombuddy"}', self.cli.hosting("list", "1111111111111111111111111111111111111111", "freedombuddy"))
        self.assertEqual('{"client": "1111111111111111111111111111111111111111", "locations": "'+date_to_use+'", "service": "freedombuddy-update-timestamp"}', self.cli.hosting("list", "1111111111111111111111111111111111111111", "freedombuddy-update-timestamp"))


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    unittest.main()
