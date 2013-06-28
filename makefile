#! /usr/bin/env make

DATA_DIR = data
BUILD_DIR = build
SCRIPTS_DIR = src/scripts
CERTIFICATE = $(DATA_DIR)/freedombuddy.crt
CFG_TEMPLATE = $(DATA_DIR)/template.cfg
CFG_PRODUCTION = $(DATA_DIR)/production.cfg
CFG_TEST = $(DATA_DIR)/test.cfg
TEST_CRYPT_FILE = test_crypt_file

freedombuddy: build ssl-certificate $(BUILD_DIR)/plinth $(SCRIPTS_DIR)/tinc_rollout $(BUILD_DIR)/python-gnupg $(CFG_PRODUCTION) $(CFG_TEST) predepend 
	@echo "Configuring FreedomBuddy for first run."
	./start.sh 0
	sleep 10
	PYTHONPATH=.:$PYTHONPATH python src/connectors/cli/controller.py --stop
	@echo ""
	@echo "Configuration complete."
	@echo "You can now start FreedomBuddy by running:"
	@echo "    bash start.sh 5"
# TODO should this run publish at some point?

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

$(BUILD_DIR)/python-gnupg: build
	test -d $(BUILD_DIR)/python-gnupg || git clone git://github.com/isislovecruft/python-gnupg.git $(BUILD_DIR)/python-gnupg
	cd $(BUILD_DIR)/python-gnupg; git pull

$(BUILD_DIR)/plinth: build
	test -d $(BUILD_DIR)/plinth || git clone git://github.com/NickDaly/Plinth.git $(BUILD_DIR)/plinth
	cd $(BUILD_DIR)/plinth; git pull

$(SCRIPTS_DIR)/tinc_rollout: build
	test -d $(SCRIPTS_DIR)/tinc_rollout || git clone git://github.com/jvasile/tinc-rollout.git $(SCRIPTS_DIR)/tinc_rollout
	cd $(SCRIPTS_DIR)/tinc_rollout; git pull

predepend:
	sudo sh -c "apt-get install python-routes python-socksipy python-cheetah python-openssl python-bjsonrpc python-cherrypy3 python-dateutil python-httplib2 python-gnupg"
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
