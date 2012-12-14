#! /bin/sh
# -*- mode: sh; mode: auto-fill; fill-column: 80 -*-

cd src

PYTHONPATH=$PYTHONPATH:../../..
PYTHONPATH=$PYTHONPATH:../build/plinth
PYTHONPATH=$PYTHONPATH:../build/python-gnupg-0.2.9
export PYTHONPATH

python tests/test_pgpprocessor.py
python tests/test_santiago.py
python tests/test_santiago_listener.py
python tests/test_gnupg.py
#python connectors/https/test_controller.py
