#!/usr/bin/env python2.7
import os, json

from angrmanagement import app

if not os.path.exists('projects'):
    os.mkdir('projects')

projects = {}
for name in os.listdir('projects'):
    try:
        json.load(open('projects/' + name + '/metadata'))
        projects[name] = []
    except (OSError, ValueError):
        pass

app.app.config['PROJECTS'] = projects
app.app.run(host='0.0.0.0', port=4321, debug=True, threaded=True)

#
# Gunicorn is super hip, but only does forking. If only I'd read the first fucking sentence on their website.
#
#import gunicorn.app.base
#class AMServer(gunicorn.app.base.BaseApplication): #pylint:disable=abstract-method
#   def __init__(self, **kwargs):
#       self.options = kwargs
#       self.application = app.app
#       super(AMServer, self).__init__()
#
#   def load_config(self):
#       config = { key:value for key,value in self.options.iteritems() if key in self.cfg.settings and value is not None }
#       for key,value in config.iteritems():
#           self.cfg.set(key.lower(), value)
#
#   def load(self):
#       return self.application

#if __name__ == '__main__':
#   import sys
#   bind = sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0'
#   port = sys.argv[2] if len(sys.argv) > 2 else 4321
#   AMServer(bind="%s:%s"%(bind,port)).run()
