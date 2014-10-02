#!/usr/bin/env python2.7
import sys

from angrmanagement import app
import rpyc

c = rpyc.connect("localhost", int(sys.argv[1]))
print c
print c.root
print c.root.projects

app.app.config['PROJECTS'] = c.root.projects
app.app.run(host='0.0.0.0', port=4321, debug=True)
