from angr/angr
maintainer yans@yancomm.net

user angr
run /home/angr/.virtualenvs/angr/bin/pip install PySide2
run cd /home/angr/angr-dev && /home/angr/.virtualenvs/angr/bin/pip install -e angr-management/
run cd /home/angr/angr-dev/angr-management && git pull
workdir /home/angr/pwd
entrypoint [ "/home/angr/.virtualenvs/angr/bin/python", "/home/angr/angr-dev/angr-management/start.py" ]
