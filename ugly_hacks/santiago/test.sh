#! /bin/sh # -*- mode: auto-fill; fill-column: 80 -*-

PYTHONPATH=$PYTHONPATH:../..
PYTHONPATH=$PYTHONPATH:/home/nick/programs/python-gnupg/python-gnupg-0.2.9
export PYTHONPATH

python test_pgpprocessor.py
python test_santiago.py
python protocols/https/test_controller.py
