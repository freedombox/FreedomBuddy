#! /usr/bin/env python # -*- mode: auto-fill; fill-column: 80 -*-
import sys
sys.path.append('build/gnupg')

import ConfigParser as configparser
import gnupg

import subprocess
from pprint import pprint



test_config_file = sys.argv[1]
test_gpg_location = sys.argv[2]
test_crypt_file = sys.argv[3]

gpg = gnupg.GPG(gnupghome=test_gpg_location)
public_keys = gpg.list_keys()
test_public_key = public_keys[0]["fingerprint"]
test_key_id = public_keys[0]["keyid"]

config = configparser.ConfigParser()
config.read(test_config_file)
config.set("pgpprocessor", "KEYID", test_public_key)


with open(test_config_file, "wb") as new_config:
	config.write(new_config)

trust_key = "gpg -e -r joe@foo.bar --homedir "+test_gpg_location+" --trusted-key " + test_key_id + " " + test_crypt_file

process = subprocess.Popen(trust_key.split(), stdout=subprocess.PIPE)
output = process.communicate()[0]
