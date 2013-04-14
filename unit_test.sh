#! /bin/sh
# -*- mode: sh; mode: auto-fill; fill-column: 80 -*-

#cd src

PYTHONPATH=$PYTHONPATH:../../..
PYTHONPATH=$PYTHONPATH:../build/gnupg
PYTHONPATH=$PYTHONPATH:../build/plinth
export PYTHONPATH

python src/tests/test_pgpprocessor.py
python src/tests/test_santiago.py
python src/tests/test_santiago_listener.py
python src/tests/test_gnupg.py
python src/connectors/https/test_controller.py
python src/tests/test_utilities.py
