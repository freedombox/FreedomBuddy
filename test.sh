#! /bin/sh
# -*- mode: sh; mode: auto-fill; fill-column: 80 -*-

cd src

PYTHONPATH=$PYTHONPATH:../../..
PYTHONPATH=$PYTHONPATH:/home/nick/programs/python-gnupg/python-gnupg-0.2.9
PYTHONPATH=$PYTHONPATH:/home/nick/programs/freedombox/plinth
export PYTHONPATH

python tests/test_pgpprocessor.py
python tests/test_santiago.py
python tests/test_gnupg.py
python connectors/https/test_controller.py
