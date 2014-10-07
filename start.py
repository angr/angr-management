#!/usr/bin/env python2.7
import sys, os, json

from angrmanagement import app
import rpyc

projects = {}
for name in os.listdir('projects'):
    try:
        json.load(open('projects/' + name + '/metadata'))
        projects[name] = []
    except:
        pass

app.app.config['PROJECTS'] = projects

app.app.run(host='0.0.0.0', port=4321, debug=True)
