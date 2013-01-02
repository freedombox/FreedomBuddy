#! /bin/sh
# -*- mode: sh; mode: auto-fill; fill-column: 80 -*-

cd src

PYTHONPATH=$PYTHONPATH:../../..
PYTHONPATH=$PYTHONPATH:/home/nick/programs/python-gnupg/python-gnupg-0.2.9
PYTHONPATH=$PYTHONPATH:/home/nick/programs/freedombox/plinth
PYTHONPATH=$PYTHONPATH:/home/nick/programs/freedombox/bjsonrpc
export PYTHONPATH

python santiago_test.py "$@"
