#!/usr/bin/env python2.7
import sys

from angrmanagement import app
import rpyc

if len(sys.argv) > 1:
    c = rpyc.connect("localhost", int(sys.argv[1]))
    app.app.config['PROJECTS'] = c.root.projects
else:
    app.app.config['PROJECTS'] = {}

app.app.run(host='0.0.0.0', port=4321, debug=True)
