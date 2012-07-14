#! /usr/bin/env make

CERTIFICATE=freedombuddy.crt

freedombuddy: build ssl-certificate build/python-gnupg production.cfg test.cfg

build:
	mkdir -p build

ssl-certificate: $(CERTIFICATE)

$(CERTIFICATE): build build/cert-depends
	sudo make-ssl-cert generate-default-snakeoil
	sudo make-ssl-cert /usr/share/ssl-cert/ssleay.cnf $(CERTIFICATE)
	sudo chgrp 1000 $(CERTIFICATE)
	sudo chmod g+r $(CERTIFICATE)
	sudo touch $(CERTIFICATE)

build/cert-depends: build
	sudo apt-get install ssl-cert
	touch build/cert-depends

build/python-gnupg: build
	-sudo apt-get install python-gnupg
	touch build/python-gnupg

production.cfg:
	cp template.cfg production.cfg

test.cfg:
	cp template.cfg test.cfg

clean:
	rm -r build

distclean: clean
	sudo rm $(CERTIFICATE)
	rm production.cfg
	rm test.cfg
