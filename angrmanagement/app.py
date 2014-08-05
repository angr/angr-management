import functools
import json
import os

import flask
from werkzeug.utils import secure_filename
import angr
from simuvex import SimIRSB, SimProcedure

from .serializer import Serializer

def jsonize(func):
    @functools.wraps(func)
    def jsonned(*args, **kwargs):
        return json.dumps(func(*args, **kwargs))
    return jsonned

app = flask.Flask(__name__, static_folder='../static')
active_projects = {}

ROOT = os.environ.get('ANGR_MANAGEMENT_ROOT', '.')
PROJDIR = ROOT + '/projects/'

@app.route('/')
def index():
    return app.send_static_file("index.html")

@app.route('/api/projects/')
@jsonize
def list_projects():
    return {name: {'name': name, 'activated': name in active_projects} for name in os.listdir(PROJDIR)}

@app.route('/api/projects/', methods=('POST',))
@jsonize
def new_project():
    file = flask.request.files['file']
    metadata = json.loads(flask.request.form['metadata'])
    name = secure_filename(metadata['name'])
    os.mkdir(PROJDIR + name)
    file.save(PROJDIR + name + '/binary')
    open(PROJDIR + name + '/metadata', 'wb').write(json.dumps(metadata))

@app.route('/api/projects/<name>/activate', methods=('POST',))
@jsonize
def activate_project(name):
    name = secure_filename(name)
    if name not in active_projects and os.path.exists(PROJDIR + name):
        metadata = json.load(open(PROJDIR + name + '/metadata', 'rb'))
        print metadata
        active_projects[name] = angr.Project(PROJDIR + name + '/binary', load_libs=False,
                                             default_analysis_mode='symbolic',
                                             use_sim_procedures=True,
                                             arch=str(metadata['arch']))

@app.route('/api/projects/<name>/cfg')
@jsonize
def get_cfg(name):
    name = secure_filename(name)
    if name in active_projects:
        cfg = active_projects[name].construct_cfg()
        serializer = Serializer()
        return {
            'nodes': [serializer.serialize(node) for node in cfg._cfg.nodes()],
            'edges': [{'from': serializer.serialize(from_, ref=True),
                       'to': serializer.serialize(to, ref=True)}
                      for from_, to in cfg._cfg.edges()]
        }

@app.route('/api/projects/<name>/ddg')
@jsonize
def get_ddg(name):
    name = secure_filename(name)
    if name in active_projects:
        proj = active_projects[name]
        ddg = angr.DDG(proj, proj.construct_cfg(), proj.entry)
        ddg.construct()
        return str(ddg._ddg)
