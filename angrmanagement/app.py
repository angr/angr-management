import functools
import json
import os

import flask

def jsonize(func):
    @functools.wraps(func)
    def jsonned(*args, **kwargs):
        return json.dumps(func(*args, **kwargs))
    return jsonned

app = flask.Flask(__name__, static_folder='../static')

@app.route('/')
def index():
    return app.send_static_file("index.html")

@app.route('/api/projects')
@jsonize
def list_projects():
    return os.listdir('projects/')
