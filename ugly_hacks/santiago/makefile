#! /usr/bin/env make

DATA_DIR = data
BUILD_DIR = build
CERTIFICATE = $(DATA_DIR)/freedombuddy.crt
CFG_TEMPLATE = $(DATA_DIR)/template.cfg
CFG_PRODUCTION = $(DATA_DIR)/production.cfg
CFG_TEST = $(DATA_DIR)/test.cfg

freedombuddy: build ssl-certificate $(BUILD_DIR)/python-gnupg $(CFG_PRODUCTION) $(CFG_TEST)

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

$(BUILD_DIR)/python-gnupg: build
	-sudo apt-get install python-gnupg
	touch $(BUILD_DIR)/python-gnupg

$(CFG_PRODUCTION):
	cp $(CFG_TEMPLATE) $(CFG_PRODUCTION)

$(CFG_TEST):
	cp $(CFG_TEMPLATE) $(CFG_TEST)

clean:
	rm -r build
