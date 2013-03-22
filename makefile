#! /usr/bin/env make

DATA_DIR = data
BUILD_DIR = build
SCRIPTS_DIR = src/scripts
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

freedombuddy: build ssl-certificate $(BUILD_DIR)/plinth $(SCRIPTS_DIR)/tinc_rollout $(BUILD_DIR)/python-gnupg $(CFG_PRODUCTION) $(CFG_TEST) create-test-key predepend 

build:
	mkdir -p build

ssl-certificate: $(CERTIFICATE)

$(CERTIFICATE): build $(BUILD_DIR)/cert-depends
ifeq ($(wildcard $(CERTIFICATE)),)
	sudo make-ssl-cert generate-default-snakeoil
	sudo make-ssl-cert /usr/share/ssl-cert/ssleay.cnf $(CERTIFICATE)
	sudo chgrp 1000 $(CERTIFICATE)
	sudo chmod g+r $(CERTIFICATE)
	sudo touch $(CERTIFICATE)
else
	echo $(CERTIFICATE) already exists
endif	

$(BUILD_DIR)/cert-depends: build
	sudo apt-get install ssl-cert
	touch $(BUILD_DIR)/cert-depends

python-gnupg-0.3.1:
	wget http://python-gnupg.googlecode.com/files/python-gnupg-0.3.1.tar.gz
	tar -xzf python-gnupg-0.3.1.tar.gz
	rm -f python-gnupg-0.3.1.tar.gz

$(BUILD_DIR)/python-gnupg: build python-gnupg-0.3.1
	rm -rf build/gnupg
	mv python-gnupg-0.3.1 build/gnupg

$(BUILD_DIR)/plinth: build
	test -d $(BUILD_DIR)/plinth || git clone git://github.com/NickDaly/Plinth.git $(BUILD_DIR)/plinth
	cd $(BUILD_DIR)/plinth; git pull

$(SCRIPTS_DIR)/tinc_rollout: build
	test -d $(SCRIPTS_DIR)/tinc_rollout || git clone git://github.com/jvasile/tinc-rollout.git $(SCRIPTS_DIR)/tinc_rollout
	cd $(SCRIPTS_DIR)/tinc_rollout; git pull

create-test-key:
ifeq ($(wildcard $(KEYS_TEST)/secring.gpg),)
	mkdir -p $(KEYS_TEST)
	chmod 700 $(KEYS_TEST)
	gpg --homedir $(KEYS_TEST) --gen-key --always-trust --batch data/test_GPG_Key_Values.cfg
	chmod 600 $(KEYS_TEST)*
	touch $(TEST_CRYPT_FILE)
	python update_test_key.py $(CFG_TEST) $(KEYS_TEST) $(TEST_CRYPT_FILE)
	rm -f $(TEST_CRYPT_FILE)*
else
	echo $(KEYS_TEST)/secring.gpg already exists
endif	

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

