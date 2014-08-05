import functools
import json
import ast
import os

import flask
from werkzeug.utils import secure_filename
import angr
from simuvex import SimIRSB, SimProcedure

try:
    import standard_logging #pylint:disable=W0611
    import angr_debug #pylint:disable=W0611
except ImportError:
    pass

from .serializer import Serializer

def jsonize(func):
    @functools.wraps(func)
    def jsonned(*args, **kwargs):
        return json.dumps(func(*args, **kwargs))
    return jsonned

app = flask.Flask(__name__, static_folder='../static')
the_serializer = Serializer()
active_projects = {}
active_surveyors = {}

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
    file = flask.request.files['file'] #pylint:disable=W0622
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
        proj = active_projects[name]
        cfg = proj.construct_cfg()
        return {
            'nodes': [the_serializer.serialize(node) for node in cfg._cfg.nodes()],
            'edges': [{'from': the_serializer.serialize(from_, ref=True),
                       'to': the_serializer.serialize(to, ref=True)}
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

#
# Surveyor functionality
#

@app.route('/api/surveyor_types')
@jsonize
def surveyor_types():
    return angr.surveyors.all_surveyors.keys()

@app.route('/api/projects/<project_name>/surveyors/new/<surveyor_type>', methods=('POST',))
@jsonize
def new_surveyor(project_name, surveyor_type):
    # TODO: take a SimExit as a starting point

    kwargs = dict(flask.request.json.get('kwargs', {}))
    for k,v in kwargs.items():
        if type(v) in (str,unicode) and v.startswith("PYTHON:"):
            kwargs[k] = ast.literal_eval(v[7:])

    p = active_projects[project_name]
    s = angr.surveyors.all_surveyors[surveyor_type](p, **kwargs)
    active_surveyors[str(id(s))] = s
    return the_serializer.serialize(s)

@app.route('/api/projects/<project_name>/surveyors')
@jsonize
def list_surveyors(project_name):
    p = active_projects[project_name]
    return [ the_serializer.serialize(s) for s in active_surveyors.itervalues() if s._project is p ]

@app.route('/api/projects/<project_name>/surveyors/<surveyor_id>')
@jsonize
def get_surveyor(project_name, surveyor_id): #pylint:disable=W0613
    return the_serializer.serialize(active_surveyors[surveyor_id])

@app.route('/api/projects/<project_name>/surveyors/<surveyor_id>/step', methods=('POST',))
@jsonize
def step_surveyors(project_name, surveyor_id): #pylint:disable=W0613
    steps = ( flask.request.json if flask.request.json is not None else flask.request.form ).get('steps', 1)
    s = active_surveyors[surveyor_id]
    s.run(n=int(steps))
    return the_serializer.serialize(s)

@app.route('/api/projects/<project_name>/surveyors/<surveyor_id>/resume/<path_id>', methods=('POST',))
@jsonize
def surveyor_resume_path(project_name, surveyor_id, path_id): #pylint:disable=W0613
    s = active_surveyors[surveyor_id]
    for list_name in s.path_lists:
        path_list = getattr(s, list_name)
        for p in path_list:
            if str(id(p)) == path_id:
                path_list.remove(p)
                s.active.append(p)
                return the_serializer.serialize(active_surveyors[surveyor_id])

@app.route('/api/projects/<project_name>/surveyors/<surveyor_id>/suspend/<path_id>', methods=('POST',))
@jsonize
def surveyor_suspend_path(project_name, surveyor_id, path_id): #pylint:disable=W0613
    s = active_surveyors[surveyor_id]
    for p in s.active:
        if str(id(p)) == path_id:
            s.active.remove(p)
            s.suspended.append(p)
            return the_serializer.serialize(active_surveyors[surveyor_id])
