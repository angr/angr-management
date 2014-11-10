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
import angr, simuvex
import rpyc
from socket import error as socket_error

try:
    import standard_logging #pylint:disable=W0611,import-error
    import angr_debug #pylint:disable=W0611,import-error
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

def with_instance(func):
    @functools.wraps(func)
    def instanced(*args, **kwargs):
        inst_id = kwargs.pop('inst_id')
        if inst_id in active_instances:
            return func(*args, instance=active_instances[inst_id], **kwargs)
        else:
            return {'success': False, 'message': 'No such instance'}
    return instanced

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
    inst, ty, _, result = active_tokens[token]
    if result.ready:
        del active_tokens[token]
        if ty == 'CFG Indicator':
            cfg = result.value.cfg
            inst['cfg'] = cfg
            return {'ready': True, 'value': {'success': True}}
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
        #metadata = json.load(open(PROJDIR + project + '/metadata', 'rb'))
        remote = spawn_child()
        active_conns.append(remote)
        inst_name = flask.request.json.get('name', '<unnamed>')
        print PROJDIR + project + '/binary'
        proj = remote.modules.angr.Project(PROJDIR + project + '/binary') # pylint: disable=no-member
        inst_name = flask.request.json.get('name', '<unnamed>')
        proj_id = create_instance(proj, inst_name, remote, project, instances)
        projects[project].append({'name': inst_name, 'id': proj_id})
        return {'success': True, 'id': proj_id}
    return {'success': False, 'message': 'Project does not exist..?'}

def create_instance(proj, inst_name, remote, project, instances):
    proj_id = id(proj)
    instance = {
        'id': proj_id,
        'name': inst_name,
        'angr': proj,
        'project': project,
        'remote': remote
    }
    instances[proj_id] = instance
    return proj_id

@app.route('/api/instances/connect', methods=('POST',))
@with_instances
@jsonize
def connect_instance(instances=None):
    hostname = flask.request.json.get('hostname', None)
    port = flask.request.json.get('port', None)
    if hostname is None or port is None:
        flask.abort(400)

    try:
        conn = rpyc.connect(hostname, port)
        conn.ping('you there?')
        pkeys = conn.root.projects.keys()
    except socket_error:
        return {'success': False, 'message': 'Connection refused.'}
    except rpyc.AsyncResultTimeout:
        return {'success': False, 'message': 'Remote unresponsive.'}
    except Exception as e: # pylint: disable=broad-except
        print e
        return {'success': False, 'message': "Couldn't connect for weird unaccounted-for reason"}
    active_conns.append(conn)

    if len(pkeys) != 1:
        return {'success': False, 'message': "There are either zero or more than one projects on this server?"}
    proj = conn.root.projects[pkeys[0]]
    proj_id = create_instance(proj, '<one-shot instance>', conn, pkeys[0], instances)
    return {'success': True, 'id': proj_id}

@app.route('/api/instances/<int:inst_id>')
@jsonize
@with_instance
def instance_info(instance=None):
    instance = instance.copy()
    proj = instance.pop('angr')
    instance.pop('remote')
    if 'cfg' in instance:
        instance.pop('cfg')
    instance['success'] = True
    instance['arch'] = the_serializer.serialize(proj.arch)
    return instance

@app.route('/api/instances/<int:inst_id>/constructCFG')
@jsonize
@with_instance
def get_cfg(instance=None):
    proj = instance['angr']
    if proj._cfg is None:
        token = str(uuid.uuid4())
        async_analyze = rpyc.async(proj.analyze)
        # that middle async_construct may look useless
        # but it maintains a strong ref to async_construct, which we need
        active_tokens[token] = (instance, 'CFG Indicator', async_analyze, async_analyze('CFG'))
        return {'token': token}
    return {'success': True}

@app.route('/api/instances/<int:inst_id>/functionManager')
@jsonize
@with_instance
def get_functions(instance=None):
    proj = instance['angr']
    if 'cfg' not in instance:
        flask.abort(400)
    return {'success': True, 'data': the_serializer.serialize(instance['cfg'].function_manager)}

@app.route('/api/instances/<int:inst_id>/irsbs', methods=('POST',))
@jsonize
@with_instance
def get_irsbs(instance=None):
    proj = instance['angr']
    out = {'irsbs': {}, 'disasm': {}}
    if not type(flask.request.json) is list:
        flask.abort(400)

    for address in flask.request.json:
        if not address.isdigit(): flask.abort(400)
        address = int(address)
        if address in proj.sim_procedures:
            if 'simProcedures' not in out:
                out['simProcedureSpots'], out['simProcedures'] = get_simproc_data(proj)
            continue
        try:
            out['irsbs'][address] = the_serializer.serialize(proj.block(address))
            dblock = proj.capper.block(address)
            for insn in dblock.insns:
                out['disasm'][insn.address] = the_serializer.serialize(insn)
        except: # pylint: disable=bare-except
            return {'success': False, 'message': 'Error translating block at 0x%x' % address}

    return {'success': True, 'data': out}

def make_simproc_name(proc):
    return str(proc)        # :(

def get_simproc_data(proj):
    locs = {addr: make_simproc_name(proc[0]) for addr, proc in proj.sim_procedures.iteritems()}
    procs = {}
    for lib in simuvex.SimProcedures.values():
        for proc in lib.values():
            procs[make_simproc_name(proc)] = {
                'prettyName': proc.__name__
            }

    return locs, procs

@app.route('/api/instances/<int:inst_id>/functions/<int:func_addr>/rename', methods=('POST',))
@jsonize
@with_instance
def rename_function(func_addr, instance=None):
    proj = instance['angr']
    if 'cfg' not in instance:
        return {'success': False, 'message': 'CFG not generated yet'}
    f = instance['cfg'].function_manager.functions[func_addr]
    f.name = flask.request.data     # oh my god
    return {'success': True}

@app.route('/api/instances/<int:inst_id>/functions/<int:func_addr>/vfg')
@jsonize
@with_instance
def get_function_vfg(func_addr, instance=None):
    vfg = angr.VFG(instance['angr'], instance['cfg'])
    vfg.construct(func_addr)
    return str(vfg)

@app.route('/api/surveyor_types')
@jsonize
def surveyor_types():
    return angr.surveyors.all_surveyors.keys()

@app.route('/api/instances/<int:inst_id>/surveyors/new', methods=('POST',))
@jsonize
@with_instance
def new_surveyor(instance=None):
    # TODO: take a SimExit as a starting point
    kwargs = dict(flask.request.json.get('kwargs', {}))
    for k,v in kwargs.items():
        if type(v) in (str,unicode) and v.startswith("PYTHON:"):
            kwargs[k] = ast.literal_eval(v[7:])

    p = instance['angr']
    surveyor_type = kwargs.pop('type')
    s = p.survey(surveyor_type, **kwargs)
    active_surveyors[str(id(s))] = s
    return {'success': True, 'data': the_serializer.serialize(s)}

@app.route('/api/instances/<int:inst_id>/surveyors')
@jsonize
@with_instance
def list_surveyors(instance):
    p = instance['angr']
    return {'success': True, 'data': [ the_serializer.serialize(s) for s in active_surveyors.itervalues() if s._project is p ]}

@app.route('/api/instances/<inst_id>/surveyors/<surveyor_id>')
@jsonize
def get_surveyor(inst_id, surveyor_id): #pylint:disable=W0613
    return {'success': True, 'data': the_serializer.serialize(active_surveyors[surveyor_id])}

@app.route('/api/instances/<inst_id>/surveyors/<surveyor_id>/step', methods=('POST',))
@jsonize
def step_surveyors(inst_id, surveyor_id): #pylint:disable=W0613
    steps = ( flask.request.json if flask.request.json is not None else flask.request.form ).get('steps', 1)
    s = active_surveyors[surveyor_id]
    s.run(n=int(steps))
    return {'success': True, 'data': the_serializer.serialize(s)}

@app.route('/api/instances/<inst_id>/surveyors/<surveyor_id>/resume/<path_id>', methods=('POST',))
@jsonize
def surveyor_resume_path(inst_id, surveyor_id, path_id): #pylint:disable=W0613
    s = active_surveyors[surveyor_id]
    for list_name in s.path_lists:
        path_list = getattr(s, list_name)
        for p in path_list:
            if p.path_id == path_id:
                path_list.remove(p)
                s.active.append(p)
                return {'success': True, 'data': the_serializer.serialize(active_surveyors[surveyor_id])}
    return {'success': False, 'message': "Path id not found"}

@app.route('/api/instances/<inst_id>/surveyors/<surveyor_id>/suspend/<path_id>', methods=('POST',))
@jsonize
def surveyor_suspend_path(inst_id, surveyor_id, path_id): #pylint:disable=W0613
    s = active_surveyors[surveyor_id]
    for p in s.active:
        if p.path_id == path_id:
            s.active.remove(p)
            s.suspended.append(p)
            return {'success': True, 'data': the_serializer.serialize(active_surveyors[surveyor_id])}
    return {'success': False, 'message': 'Path id not found'}

@app.route('/download/<project>')
def download_project_binary(project):
    if project not in os.listdir(PROJDIR):
        flask.abort(404)
    return flask.send_file(os.getcwd() + '/' + PROJDIR + project + '/binary')
