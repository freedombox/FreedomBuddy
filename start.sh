#! /bin/sh
# -*- mode: sh; mode: auto-fill; fill-column: 80 -*-


PYTHONPATH=build/gnupg:$PYTHONPATH
PYTHONPATH=build/plinth:$PYTHONPATH
PYTHONPATH=build/bjsonrpc:$PYTHONPATH
export PYTHONPATH


if [ "$1" -eq "0" ]
then
    # initial run
    python src/santiago_run.py -d &

elif [ "$1" -eq "1" ]
then
    # start santiago
    python src/santiago_run.py "$@"

elif [ "$1" -eq "2" ]
then
    # supply the cli controller any action.
    python src/connectors/cli/controller.py "$@"

elif [ "$1" -eq "3" ]
then
    # supply the cli controller any action.
    python src/connectors/https/controller.py "--listen"

elif [ "$1" -eq "4" ]
then
    # give the https controller any action.
    python src/connectors/https/controller.py "--monitor"

elif [ "$1" -eq "5" ]
then
    # do EVERYTHING in multiple terminals.

    # start fbuddy + cli client
    lxterm -e "python src/santiago_run.py" &

    # start https client
    lxterm -e "python src/connectors/https/controller.py --listen" &
    lxterm -e "python src/connectors/https/controller.py --monitor" &

    # start a browser for the monitor
    lxterm -e "sleep 5 && x-www-browser https://127.0.0.1:8081/freedombuddy" &

    echo "Press return to quit."
    read X
    killall python
fi
