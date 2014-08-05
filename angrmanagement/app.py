import functools
import json
import os

import flask
from werkzeug.utils import secure_filename

def jsonize(func):
    @functools.wraps(func)
    def jsonned(*args, **kwargs):
        return json.dumps(func(*args, **kwargs))
    return jsonned

app = flask.Flask(__name__, static_folder='../static')

ROOT = os.environ.get('ANGR_MANAGEMENT_ROOT', '.')
PROJDIR = ROOT + '/projects/'

@app.route('/')
def index():
    return app.send_static_file("index.html")

@app.route('/api/projects')
@jsonize
def list_projects():
    return os.listdir(PROJDIR)

@app.route('/api/projects', methods=('POST',))
@jsonize
def new_project():
    file = flask.request.files['file']
    metadata = json.loads(flask.request.form['metadata'])
    name = secure_filename(metadata['name'])
    os.mkdir(PROJDIR + name)
    file.save(PROJDIR + name + '/binary')
    open(PROJDIR + name + '/metadata', 'wb').write(json.dumps(metadata))
