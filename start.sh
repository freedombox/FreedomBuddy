#! /bin/sh
# -*- mode: sh; mode: auto-fill; fill-column: 80 -*-

cd src

PYTHONPATH=$PYTHONPATH:../../..
PYTHONPATH=$PYTHONPATH:../build/gnupg
PYTHONPATH=$PYTHONPATH:../build/plinth
PYTHONPATH=$PYTHONPATH:../build/bjsonrpc
export PYTHONPATH

if [ "$1" -eq "1" ]
then
    python santiago_test.py "$@"
elif [ "$1" -eq "2" ]
then
    python connectors/cli/controller.py --action list
fi
