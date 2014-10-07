import functools
import json
import ast
import os
import random
import subprocess
import time
import uuid

import flask
from werkzeug.utils import secure_filename
import angr
from simuvex import SimIRSB, SimProcedure
import rpyc
from rpyc.utils.classic import obtain

try:
    import standard_logging #pylint:disable=W0611
    import angr_debug #pylint:disable=W0611
except ImportError:
    pass

from .serializer import Serializer

def spawn_child():
    port = random.randint(30000, 39999)
    cmd = ['python', '-c', '''from rpyc.core import SlaveService
#import logging
#logging.basicConfig(filename='child.log', level=logging.DEBUG)
from rpyc.utils.server import OneShotServer
OneShotServer(SlaveService, hostname='localhost', port={}).start()
'''.format(port)]
    subprocess.Popen(cmd)
    time.sleep(2.0)
    return rpyc.classic.connect('localhost', port)

def jsonize(func):
    @functools.wraps(func)
    def jsonned(*args, **kwargs):
        result = func(*args, **kwargs)
        return json.dumps(result)
    return jsonned

def with_projects(func):
    @functools.wraps(func)
    def projectsed(*args, **kwargs):
        return func(*args, projects=app.config['PROJECTS'], **kwargs)
    return projectsed

def with_instances(func):
    @functools.wraps(func)
    def instancesed(*args, **kwargs):
        return func(*args, instances=active_instances, **kwargs)
    return instancesed

app = flask.Flask(__name__, static_folder='../static')
the_serializer = Serializer()
active_tokens = {}
active_surveyors = {}
active_conns = []
active_instances = {}

ROOT = os.environ.get('ANGR_MANAGEMENT_ROOT', '.')
PROJDIR = ROOT + '/projects/'

@app.route('/')
def index():
    return app.send_static_file("index.html")

@app.route('/api/tokens/<token>')
@jsonize
def redeem(token):
    if token not in active_tokens:
        flask.abort(400)
    ty, async_thing, result = active_tokens[token]
    if result.ready:
        del active_tokens[token]
        if ty == 'CFG':
            cfg = result.value
            return {'ready': True, 'value': {
                'nodes': [the_serializer.serialize(node) for node in cfg._cfg.nodes()],
                'edges': [{'from': the_serializer.serialize(from_, ref=True),
                           'to': the_serializer.serialize(to, ref=True)}
                          for from_, to in cfg._cfg.edges()],
                'functions': {addr: obtain(f.basic_blocks) for addr, f in cfg.get_function_manager().functions.items()},
            }}
    else:
        return {'ready': False}

@app.route('/api/projects/')
@with_projects
@jsonize
def list_projects(projects=None):
    # Makes sure the PROJDIR exists
    if not os.path.exists(PROJDIR):
        os.makedirs(PROJDIR)
    return [{'name': name, 'instances': instances} for name, instances in projects.iteritems()]

@app.route('/api/projects/new', methods=('POST',))
@with_projects
@jsonize
def new_project(projects=None):
    file = flask.request.files['file'] #pylint:disable=W0622
    metadata = json.loads(flask.request.form['metadata'])
    name = secure_filename(metadata['name'])
    if name in projects or os.path.exists(PROJDIR + name):
        return {'success': False, 'message': "Name already in use"}

    os.mkdir(PROJDIR + name)
    file.save(PROJDIR + name + '/binary')
    open(PROJDIR + name + '/metadata', 'wb').write(json.dumps(metadata))
    projects[name] = []
    return {'success': True, 'name': name}

@app.route('/api/instances')
@with_instances
@jsonize
def list_instances(instances=None):
    return {inst_id: {'name': inst['name'], 'project': inst['project']} for inst_id, inst in instances.iteritems()}
        

@app.route('/api/instances/new/<project>', methods=('POST',))
@with_projects
@with_instances
@jsonize
def new_instance(project, projects=None, instances=None):
    if project in projects:
        metadata = json.load(open(PROJDIR + project + '/metadata', 'rb'))
        remote = spawn_child()
        active_conns.append(remote)
        print 'LOOK:', os.path.exists(PROJDIR + project + '/binary')
        proj = remote.modules.angr.Project(PROJDIR + project + '/binary')
        proj_id = id(proj)
        inst_name = flask.request.json.get('name', '<unnamed>')
        instance = {
            'id': proj_id,
            'name': inst_name,
            'angr': proj,
            'project': project,
            'remote': remote
        }
        instances[proj_id] = instance
        projects[project].append({'name': inst_name, 'id': proj_id})
        return {'success': True, 'id': proj_id}
    return {'success': False, 'message': 'Project does not exist..?'}

@app.route('/api/instances/<int:inst_id>')
@with_instances
@jsonize
def instance_info(inst_id, instances=None):
    if inst_id in instances:
        instance = instances[inst_id].copy()
        instance.pop('angr')
        instance.pop('remote')
        instance['success'] = True
        return instance
    return {'success': False, 'message': 'No such instance'}

@app.route('/api/instances/<int:inst_id>/cfg')
@with_instances
@jsonize
def get_cfg(inst_id, instances=None):
    if inst_id in instances:
        instance = instances[inst_id]
        proj = instance['angr']
        token = str(uuid.uuid4())
        if proj._cfg is None:
            async_construct = rpyc.async(proj.construct_cfg)
            active_tokens[token] = ('CFG', async_construct, async_construct())
            return {'token': token}
        cfg = proj._cfg
        return {
            'nodes': [the_serializer.serialize(node) for node in cfg._cfg.nodes()],
            'edges': [{'from': the_serializer.serialize(from_, ref=True),
                       'to': the_serializer.serialize(to, ref=True)}
                      for from_, to in cfg._cfg.edges()],
            'functions': {addr: obtain(f.basic_blocks) for addr, f in cfg.get_function_manager().functions.items()},
        }

@app.route('/api/instances/<int:inst_id>/ddg')
@with_instances
@jsonize
def get_ddg(inst_id, instances=None):
    if inst_id in instances:
        instance = instances[inst_id]
        proj = instance['angr']
        ddg = angr.DDG(proj, proj.construct_cfg() if proj._cfg is None else proj._cfg, proj.entry)
        ddg.construct()
        return str(ddg._ddg)

def disasm(binary, block):
    return '\n'.join(binary.ida.idc.GetDisasm(s.addr)
                     for s in block.statements() if s.__class__.__name__ == 'IMark')

# @app.route('/api/projects/<name>/dis/<int:block_addr>')
# @with_projects
# #@jsonize
# def get_dis(name, block_addr, projects=None):
#     name = secure_filename(name)
#     if name in projects:
#         proj = active_projects[name]
#         block = proj.block(block_addr)
#         # import ipdb; ipdb.set_trace()
#         return disasm(proj.main_binary, block)

#
# Surveyor functionality
#

@app.route('/api/surveyor_types')
@jsonize
def surveyor_types():
    return angr.surveyors.all_surveyors.keys()

@app.route('/api/instances/<int:inst_id>/surveyors/new/<surveyor_type>', methods=('POST',))
@jsonize
@with_instances
def new_surveyor(inst_id, surveyor_type, instances=None):
    # TODO: take a SimExit as a starting point

    kwargs = dict(flask.request.json.get('kwargs', {}))
    for k,v in kwargs.items():
        if type(v) in (str,unicode) and v.startswith("PYTHON:"):
            kwargs[k] = ast.literal_eval(v[7:])

    p = instances[inst_id]['angr']
    s = p.survey(surveyor_type, **kwargs)
    active_surveyors[str(id(s))] = s
    return the_serializer.serialize(s)

@app.route('/api/instances/<int:inst_id>/surveyors')
@jsonize
@with_instances
def list_surveyors(inst_id, instances=None):
    p = instances[inst_id]['angr']
    return [ the_serializer.serialize(s) for s in active_surveyors.itervalues() if s._project is p ]

@app.route('/api/instances/<inst_id>/surveyors/<surveyor_id>')
@jsonize
def get_surveyor(inst_id, surveyor_id): #pylint:disable=W0613
    return the_serializer.serialize(active_surveyors[surveyor_id])

@app.route('/api/instances/<inst_id>/surveyors/<surveyor_id>/step', methods=('POST',))
@jsonize
def step_surveyors(inst_id, surveyor_id): #pylint:disable=W0613
    steps = ( flask.request.json if flask.request.json is not None else flask.request.form ).get('steps', 1)
    s = active_surveyors[surveyor_id]
    s.run(n=int(steps))
    return the_serializer.serialize(s)

@app.route('/api/instances/<inst_id>/surveyors/<surveyor_id>/resume/<path_id>', methods=('POST',))
@jsonize
def surveyor_resume_path(inst_id, surveyor_id, path_id): #pylint:disable=W0613
    s = active_surveyors[surveyor_id]
    for list_name in s.path_lists:
        path_list = getattr(s, list_name)
        for p in path_list:
            if str(id(p)) == path_id:
                path_list.remove(p)
                s.active.append(p)
                return the_serializer.serialize(active_surveyors[surveyor_id])

@app.route('/api/instances/<inst_id>/surveyors/<surveyor_id>/suspend/<path_id>', methods=('POST',))
@jsonize
def surveyor_suspend_path(inst_id, surveyor_id, path_id): #pylint:disable=W0613
    s = active_surveyors[surveyor_id]
    for p in s.active:
        if str(id(p)) == path_id:
            s.active.remove(p)
            s.suspended.append(p)
            return the_serializer.serialize(active_surveyors[surveyor_id])

@app.route('/download/<project>')
def download_project_binary(project):
    if project not in os.listdir(PROJDIR):
        flask.abort(404)
    return flask.send_file(os.getcwd() + '/' + PROJDIR + project + '/binary')
