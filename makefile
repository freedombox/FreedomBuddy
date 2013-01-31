#! /usr/bin/env make

DATA_DIR = data
BUILD_DIR = build
CERTIFICATE = $(DATA_DIR)/freedombuddy.crt
CFG_TEMPLATE = $(DATA_DIR)/template.cfg
CFG_PRODUCTION = $(DATA_DIR)/production.cfg
CFG_TEST = $(DATA_DIR)/test.cfg
KEYS_TEST = $(DATA_DIR)/test_gpg_home/
KEYS_EXPIRED_TEST = $(DATA_DIR)/test_expired_gpg_home/
TEST_CRYPT_FILE = test_crypt_file
TEST_EXPIRED_KEY_DATA_ORIGINAL = $(DATA_DIR)/F57526CDF701605B1DAB2A64F111ED7A4F7B0542_original.dat
TEST_EXPIRED_KEY_DATA_TO_USE = $(DATA_DIR)/F57526CDF701605B1DAB2A64F111ED7A4F7B0542.dat
TEST_EXPIRED_SUB_KEY_DATA_ORIGINAL = $(DATA_DIR)/6772C6B2742E65C074D574D96F9E1C1A2524ED04_original.dat
TEST_EXPIRED_SUB_KEY_DATA_TO_USE = $(DATA_DIR)/6772C6B2742E65C074D574D96F9E1C1A2524ED04.dat

freedombuddy: build ssl-certificate $(BUILD_DIR)/plinth $(BUILD_DIR)/python-gnupg $(CFG_PRODUCTION) $(CFG_TEST) create-test-key create-expired-test-key predepend

build:
	mkdir -p build

ssl-certificate: $(CERTIFICATE)

$(CERTIFICATE): build $(BUILD_DIR)/cert-depends
	sudo make-ssl-cert generate-default-snakeoil
	sudo make-ssl-cert /usr/share/ssl-cert/ssleay.cnf $(CERTIFICATE)
	sudo chgrp 1000 $(CERTIFICATE)
	sudo chmod g+r $(CERTIFICATE)
	sudo touch $(CERTIFICATE)

$(BUILD_DIR)/cert-depends: build
	sudo apt-get install ssl-cert
	touch $(BUILD_DIR)/cert-depends

python-gnupg-0.3.1:
	wget http://python-gnupg.googlecode.com/files/python-gnupg-0.3.1.tar.gz
	tar -xzf python-gnupg-0.3.1.tar.gz
	rm -f python-gnupg-0.3.1.tar.gz

$(BUILD_DIR)/python-gnupg: build python-gnupg-0.3.1
	mv python-gnupg-0.3.1 build/gnupg

$(BUILD_DIR)/plinth: build
	git clone git://github.com/NickDaly/Plinth.git $(BUILD_DIR)/plinth

create-test-key:
	mkdir $(KEYS_TEST)
	chmod 700 $(KEYS_TEST)
	gpg --homedir $(KEYS_TEST) --gen-key --always-trust --batch data/test_GPG_Key_Values.cfg
	chmod 600 $(KEYS_TEST)*
	touch $(TEST_CRYPT_FILE)
	python update_test_key.py $(CFG_TEST) $(KEYS_TEST) $(TEST_CRYPT_FILE)
	rm -f $(TEST_CRYPT_FILE)*

create-expired-test-key:
	cp $(TEST_EXPIRED_KEY_DATA_ORIGINAL) $(TEST_EXPIRED_KEY_DATA_TO_USE)
	cp $(TEST_EXPIRED_SUB_KEY_DATA_ORIGINAL) $(TEST_EXPIRED_SUB_KEY_DATA_TO_USE)
	chmod 700 $(KEYS_EXPIRED_TEST)
	chmod 600 $(KEYS_EXPIRED_TEST)*

predepend:
	sudo sh -c "apt-get install python-routes python-socksipy python-cheetah python-openssl python-bjsonrpc"
	touch predepend

$(CFG_PRODUCTION):
	cp $(CFG_TEMPLATE) $(CFG_PRODUCTION)

$(CFG_TEST):
	cp $(CFG_TEMPLATE) $(CFG_TEST)

clean:
	rm -rf build
	rm -f $(CERTIFICATE)
	rm -rf $(KEYS_TEST)
	rm -f $(TEST_CRYPT_FILE)*
	rm -f predepend

