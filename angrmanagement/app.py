#pylint:disable=C0111,C0103

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
from .explorer import InteractiveExplorer

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
        return json.dumps(result, ensure_ascii=False)
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

the_serializer = Serializer()
def serialize(*args, **kwargs):
    return the_serializer.serialize(*args, **kwargs)

app = flask.Flask(__name__, static_folder='../static')
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
    inst, token_type, _, result = active_tokens[token]
    if result.ready:
        del active_tokens[token]
        if token_type == 'CFG Indicator':
            cfg = result.value
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
    return [
        {'name': name, 'instances': instances}
        for name, instances in
        projects.iteritems()
    ]

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
    return {
        inst_id: {'name': inst['name'], 'project': inst['project']}
        for inst_id, inst
        in instances.iteritems()
    }


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
        proj = remote.modules.angr.Project(str(PROJDIR + project + '/binary')) # pylint: disable=no-member
        inst_name = flask.request.json.get('name', '<unnamed>')
        explorer = InteractiveExplorer(proj)
        proj_id = create_instance(proj, explorer, inst_name, remote, project, instances)
        projects[project].append({'name': inst_name, 'id': proj_id})
        return {'success': True, 'id': proj_id}
    return {'success': False, 'message': 'Project does not exist..?'}

def create_instance(proj, explorer, inst_name, remote, project, instances):
    proj_id = id(proj)
    instance = {
        'id': proj_id,
        'name': inst_name,
        'angr': proj,
        'project': project,
        'explorer': explorer,
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
    except Exception as exc: # pylint: disable=broad-except
        print exc
        return {
            'success': False,
            'message': "Couldn't connect for weird unaccounted-for reason"
        }
    active_conns.append(conn)

    if len(pkeys) != 1:
        return {
            'success': False,
            'message': "There are either zero or more than one projects" \
                     + " on this server?"
        }
    proj = conn.root.projects[pkeys[0]]
    explorer = InteractiveExplorer(proj)
    proj_id = create_instance(proj, explorer, '<one-shot instance>', conn, pkeys[0], instances)
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
    if 'explorer' in instance:
        instance.pop('explorer')
    instance['success'] = True
    instance['arch'] = serialize(proj.arch)
    return instance

@app.route('/api/instances/<int:inst_id>/constructCFG')
@jsonize
@with_instance
def get_cfg(instance=None):
    proj = instance['angr']
    if 'cfg' not in instance:
        token = str(uuid.uuid4())
        async_analyze = rpyc.async(proj.analyze)
        # that middle async_construct may look useless
        # but it maintains a strong ref to async_construct, which we need
        active_tokens[token] = (instance, 'CFG Indicator',
                                async_analyze, async_analyze('CFG'))
        return {'token': token}
    return {'success': True}

@app.route('/api/instances/<int:inst_id>/functionManager')
@jsonize
@with_instance
def get_functions(instance=None):
    if 'cfg' not in instance:
        flask.abort(400)
    return {
        'success': True,
        'data': serialize(instance['cfg'].function_manager)
    }

@app.route('/api/instances/<int:inst_id>/irsbs', methods=('POST',))
@jsonize
@with_instance
def get_irsbs(instance=None):
    proj = instance['angr']
    out = {'irsbs': {}, 'disasm': {}}
    if not type(flask.request.json) is list:
        flask.abort(400)

    for address in flask.request.json:
        if not address.isdigit():
            flask.abort(400)
        address = int(address)
        if address in proj.sim_procedures:
            if 'simProcedures' not in out:
                out['simProcedureSpots'], \
                    out['simProcedures'] = get_simproc_data(proj)
            continue
        try:
            out['irsbs'][address] = serialize(proj.block(address))
            dblock = proj.capper.block(address)
            for insn in dblock.insns:
                out['disasm'][insn.address] = serialize(insn)
        except: # pylint: disable=bare-except
            return {
                'success': False,
                'message': 'Error translating block at 0x%x' % address
            }

    return {'success': True, 'data': out}

def make_simproc_name(proc):
    return str(proc)        # :(

def get_simproc_data(proj):
    locs = {
        addr: make_simproc_name(proc[0])
        for addr, proc
        in proj.sim_procedures.iteritems()
    }
    procs = {}
    for lib in simuvex.SimProcedures.values():
        for proc in lib.values():
            procs[make_simproc_name(proc)] = {
                'prettyName': proc.__name__
            }

    return locs, procs

@app.route('/api/instances/<int:inst_id>/functions/<int:func_addr>/rename',
           methods=('POST',))
@jsonize
@with_instance
def rename_function(func_addr, instance=None):
    if 'cfg' not in instance:
        return {'success': False, 'message': 'CFG not generated yet'}
    func = instance['cfg'].function_manager.functions[func_addr]
    func.name = flask.request.data     # oh my god
    return {'success': True}

@app.route('/api/instances/<int:inst_id>/functions/<int:func_addr>/vfg')
@jsonize
@with_instance
def get_function_vfg(func_addr, instance=None):
    vfg = angr.VFG(instance['angr'], instance['cfg'])
    vfg.construct(func_addr)
    return str(vfg)

@app.route('/api/instances/<int:inst_id>/explore/paths')
@jsonize
@with_instance
def get_explore_paths(instance=None):
    return {'success': True, 'data': serialize(instance['explorer'].all_paths)}

@app.route('/api/instances/<int:inst_id>/explore/paths', methods=('POST',))
@jsonize
@with_instance
def new_path(instance=None):
    ex = instance['explorer']
    p = instance['angr']
    if flask.request.json['type'] == 'entry_point':
        path = p.path_generator.entry_point()
    else:
        return {'success': False, 'message': 'unrecognized path type'}
    ex.active.append(path)
    return {'success': True, 'data': serialize(path)}

@app.route('/api/instances/<int:inst_id>/explore/paths/<path_id>/step', methods=('POST',))
@jsonize
@with_instance
def step_path(path_id, instance=None):
    ex = instance['explorer']
    successors = ex.step_path_by_id(path_id)
    return {'success': True, 'data': serialize(successors)}

@app.route('/api/instances/<int:inst_id>/explore')
@jsonize
@with_instance
def explore(instance=None):
    pass

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
    for key, val in kwargs.iteritems():
        if isinstance(val, (str, unicode)) and val.startswith("PYTHON:"):
            kwargs[key] = ast.literal_eval(val[7:])

    proj = instance['angr']
    surveyor_type = kwargs.pop('type')
    surveyor = proj.survey(surveyor_type, **kwargs) #pylint:disable=W0142
    active_surveyors[str(id(surveyor))] = surveyor
    return {'success': True, 'data': serialize(surveyor)}

@app.route('/api/instances/<int:inst_id>/surveyors')
@jsonize
@with_instance
def list_surveyors(instance):
    proj = instance['angr']
    return {
        'success': True,
        'data': [
            serialize(s)
            for s
            in active_surveyors.itervalues()
            if s._project is proj #pylint:disable=W0212
        ]
    }

@app.route('/api/instances/<inst_id>/surveyors/<surveyor_id>')
@jsonize
def get_surveyor(inst_id, surveyor_id): #pylint:disable=W0613
    return {'success': True, 'data': serialize(active_surveyors[surveyor_id])}

@app.route('/api/instances/<inst_id>/surveyors/<surveyor_id>/step',
           methods=('POST',))
@jsonize
def step_surveyors(inst_id, surveyor_id): #pylint:disable=W0613
    req_data = flask.request.json \
               if flask.request.json is not None \
               else flask.request.form
    steps = req_data.get('steps', 1)
    surveyor = active_surveyors[surveyor_id]
    surveyor.run(n=int(steps))
    surveyor.prune()
    return {'success': True, 'data': serialize(surveyor)}

@app.route('/api/instances/<inst_id>/surveyors/<surveyor_id>/resume/<path_id>',
           methods=('POST',))
@jsonize
def surveyor_resume_path(inst_id, surveyor_id, path_id): #pylint:disable=W0613
    surveyor = active_surveyors[surveyor_id]
    for list_name in surveyor.path_lists:
        path_list = getattr(surveyor, list_name)
        for path in path_list:
            if path.path_id == path_id:
                path_list.remove(path)
                surveyor.active.append(path)
                return {
                    'success': True,
                    'data': serialize(active_surveyors[surveyor_id])
                }
    return {'success': False, 'message': "Path id not found"}

@app.route('/api/instances/<inst_id>/surveyors/<surveyor_id>/paths/<path_id>/expr_val',
           methods=('POST',))
@jsonize
def surveyor_expr_val(inst_id, surveyor_id, path_id): #pylint:disable=W0613
    surveyor = active_surveyors[surveyor_id]
    for list_name in surveyor.path_lists:
        path_list = getattr(surveyor, list_name)
        for maybe_path in path_list:
            if maybe_path.path_id == path_id:
                path = maybe_path
                break
        else:
            continue
        break
    else:
        return {'success': False, 'message': "Path id not found"}

    req_data = flask.request.json \
               if flask.request.json is not None \
               else flask.request.form

    state = path.state
    before_stmt = req_data.get('before', None)

    expr_type = req_data['expr_type']
    if expr_type == 'reg':
        reg = req_data['reg']
        for act in state.log.events:
            print act.stmt_idx, act.type, act.action
            if act.stmt_idx >= before_stmt or act.type != 'reg' \
               or act.action != 'write':
                continue

            if act.objects['offset'].ast == reg:
                expr = act.objects['data'].ast
                break
        else:
            # THIS IS WRONG
            expr = state.reg_expr(reg)

        return {
            'success': True,
            'data': serialize(state.simplify(expr))
        }

    return {
        'success': False,
        'message': 'Unknown expr type',
    }

@app.route('/api/instances/<int:inst_id>/explore/paths/<path_id>/state')
@jsonize
@with_instance
def get_state_of_path(path_id, instance=None):
    ex = instance['explorer']
    path = ex.path_by_id(path_id)
    return {
        'success': True,
        'data': serialize(path.state),
    }

@app.route('/api/instances/<inst_id>/surveyors/<surveyor_id>/suspend/<path_id>',
           methods=('POST',))
@jsonize
def surveyor_suspend_path(inst_id, surveyor_id, path_id): #pylint:disable=W0613
    surveyor = active_surveyors[surveyor_id]
    for path in surveyor.active:
        if path.path_id == path_id:
            surveyor.active.remove(path)
            surveyor.suspended.append(path)
            return {
                'success': True,
                'data': serialize(active_surveyors[surveyor_id])
            }
    return {'success': False, 'message': 'Path id not found'}

@app.route('/download/<project>')
def download_project_binary(project):
    if project not in os.listdir(PROJDIR):
        flask.abort(404)
    return flask.send_file(os.getcwd() + '/' + PROJDIR + project + '/binary')
