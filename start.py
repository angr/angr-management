#!/usr/bin/env python2.7
import sys

from angrmanagement import app
import rpyc

c = rpyc.connect("localhost", int(sys.argv[1]))
print c
print c.root

app.app.config['PROJECTS'] = c.root.projects
app.app.run(port=4321, debug=True)
