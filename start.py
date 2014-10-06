#!/usr/bin/env python2.7
import sys, os, json

from angrmanagement import app
import rpyc

projects = {}
for name in os.listdir('projects'):
    try:
        json.load(open('projects/' + name + '/metadata'))
        projects[name] = None
    except:
        pass

if len(sys.argv) > 1:
    c = rpyc.connect("localhost", int(sys.argv[1]))
    for name, proj in c.root.projects.iteritems():
        if name in projects:
            print '** Warning: Project name %s found in both projects dir and connected AngrServer. Using connected project.'
        projects[name] = proj

app.app.config['PROJECTS'] = projects

app.app.run(host='0.0.0.0', port=4321, debug=True)
