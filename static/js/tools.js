'use strict';

var tools = angular.module('angr.tools', ['angr.comm']);

tools.directive('numberBase', function(){
    return {
        require: 'ngModel',
        link: function(scope, ele, attrs, ctrl){
            ctrl.$parsers.unshift(function(viewValue){
                return parseInt(viewValue, parseInt(attrs.numberBase));
            });

            ctrl.$formatters.push(function(modelValue){
                var base = parseInt(attrs.numberBase);
                var s = parseInt(modelValue, 10).toString(base);
                return s;
            });
        }
    };
});

tools.directive('onEnter', function () {
    return function (scope, element, attrs) {
        element.bind("keydown keypress", function (event) {
            if (event.which === 13) {
                scope.$apply(function () {
                    scope.$eval(attrs.onEnter, {'event': event});
                });

                event.preventDefault();
            }
        });
    };
});

tools.directive('realClick', function () {
    return function (scope, element, attrs) {
        var sx = 0,
            sy = 0,
            funcExpr = attrs.realClick;
        element.bind("mousedown", function (e) {
            sx = e.pageX;
            sy = e.pageY;
        });

        element.bind("mouseup", function (e) {
            var dx = Math.abs(sx - e.pageX),
                dy = Math.abs(sy - e.pageY);
            if (dy < 5 && dx < 5) {
                scope.$apply(function () {
                    scope.$eval(funcExpr, {'event': e});
                });
            }
        });
    };
});

tools.factory('Schedule', function ($timeout) {
    return function (callback) {
        $timeout(callback, 0);
    };
});

tools.filter('funcname', function () {
    return function (func) {
        if (func.name === null) {
            var x = 'sub_' + parseInt(func.address.toString(), 10).toString(16);
            func.name = x;
        } else {
            return func.name;    // ugh.
        }
    };
});

tools.filter('funcnameextra', function () {
    return function (func) {
        var x;
        if (func.name === null) {
            x = 'sub_' + parseInt(func.address.toString(), 10).toString(16);
        } else {
            x = func.name;
        }
        return x + ' (0x' + parseInt(func.address.toString(), 10).toString(16) + ')';
    };
});

tools.filter('hexpad', function () {
    return function (str) {     // Accounts for decimal strings, ew
        var x = parseInt(str.toString(), 10).toString(16);
        while (x.length < 8) { // TODO: less hax
            x = '0' + x;
        }
        return x;
    };
});

tools.filter('hex', function () {
    return function (str) {     // Accounts for decimal strings, ew
        return parseInt(str.toString(), 10).toString(16);
    };
});

tools.factory('A', function() {
    function A(op, args, length, variables, symbolic, backend, hash) {
        this.op = op;
        this.args = args;
        this.length = length;
        this.variables = variables;
        this.symbolic = symbolic;
        this.backend = backend;
        this.hash = hash;
    }

    return A;
});

tools.factory('BVV', function() {
    function BVV(value, length) {
        this.value = value;
        this.length = length;
    }

    return BVV;
});

tools.factory('BranchingDict', function() {
    function BranchingDict(cowdict) {
        var that = this;
        Object.keys(cowdict).forEach(function (v) {
            that[v] = cowdict[v];
        });
    }
    return BranchingDict;
});

tools.factory('BackedDict', function() {
    function BackedDict(storage, deletes, backers) {
        var that = this;

        backers.forEach(function (d) {
            Object.keys(d).forEach(function (v) {
                that[v] = d[v];
            });
        });

        Object.keys(storage).forEach(function (v) {
            that[v] = storage[v];
        });

        Object.keys(deletes).forEach(function (v) {
            delete this[v];
        });
    }

    return BackedDict;
});

tools.factory('SimPagedMemory', function() {
    function SimPagedMemory(backer, pages, page_size, name_mapping, hash_mapping) {
        this.backer = backer;
        this.pages = pages;
        this.page_size = page_size;
        this.name_mapping = name_mapping;

        this.getMemoryObject = function(i) {
            var page_num = Math.trunc(i/this.page_size);
            var page_idx = i % this.page_size;

            if (!(page_num in pages)) { return undefined; }
            return pages[page_num][page_idx];
        };
    }

    return SimPagedMemory;
});

tools.factory('anaLoad', function(A, BVV, BranchingDict, BackedDict, SimPagedMemory) {
    return function deserialize(value, objects, cache) {
        if (typeof cache === 'undefined') {
            cache = {};
        }

        //if (value != null && (typeof value === 'object') && ('class' in value)) console.log("Value:", value);

        if (value === null) {
            return null;
        } else if (typeof value === 'object' && 'ana_uuid' in value) {
            if (value.ana_uuid in cache) {
                return cache[value.ana_uuid];
            } else {
                cache[value.ana_uuid] = {}
                var obj = deserialize(objects[value.ana_uuid], objects, cache);
                angular.extend(cache[value.ana_uuid], obj);
                return obj;
            }
        } else if (typeof value === 'object') {
            if (value instanceof Array) {
                return value.map(function(o) { return deserialize(o, objects, cache); });
            } else if (value['class'] === 'FinalizableDict') {
                var f = deserialize(value.object[0], objects, cache);
                //console.log("FinalizableDict:",f);
                return f;
            } else if (value['class'] === 'BranchingDict') {
                return new BranchingDict(deserialize(value.object.cowdict, objects, cache));
            } else if (value['class'] === 'SimPagedMemory') {
                var backer = deserialize(value.object.backer, objects, cache);
                var pages = deserialize(value.object.pages, objects, cache);
                var page_size = deserialize(value.object.page_size, objects, cache);
                var name_mapping = deserialize(value.object.name_mapping, objects, cache);
                var hash_mapping = deserialize(value.object.hash_mapping, objects, cache);
                var spm = new SimPagedMemory(backer, pages, page_size, name_mapping, hash_mapping);
                //console.log(spm);
                return spm;
            } else if (value['class'] === 'BackedDict') {
                var storage = deserialize(value.object[0], objects, cache);
                var deletes = deserialize(value.object[1], objects, cache);
                var backers = deserialize(value.object[2], objects, cache);
                return new BackedDict(storage, deletes, backers);
            } else if (!('class' in value) || typeof value.object === 'object') {
                var des = { };
                var thing = 'class' in value ? value.object : value;
                for (var key in thing) {
                    des[key] = deserialize(thing[key], objects, cache);
                }
                //des.class = value.class
                return des;
            } else if (value['class'] === 'A' || value['class'] === 'I') {
                var deserializedArgs = value.object[1].map(function(o) { return deserialize(o, objects, cache); });
                return new A(value.object[0], deserializedArgs, value.object[2], value.object[3], value.object[4], value.object[5], value.object[6]);
            } else if (value['class'] === 'BVV') {
                return new BVV(value.object[0], value.object[1]);
            } else {
                throw new Error("unrecognized deserialization thing");
            }
        } else if (['boolean', 'string', 'number'].indexOf(typeof value) >= 0) {
            return value;
        } else {
            console.log(value);
            throw new Error("unrecognized type");
        }
    };
});

// Okay here's the big one

tools.factory('AngrData', function ($q, $http, $timeout, globalCommunicator, anaLoad) {
    var angrdata = {}, GET, POST, genEmptyPromise, genericRequest, addSurveyor, addPath;
    angrdata.gcomm = globalCommunicator;

    GET = function (url) {
        return {
            method: 'GET',
            url: url
        };
    };

    POST = function (url, data) {
        return {
            method: 'POST',
            url: url,
            data: data
        };
    };

    genEmptyPromise = function () { // haha
        var deferred = $q.defer();
        deferred.resolve();
        return deferred.promise;
    };

    genericRequest = function (config) {
        return $http(config).then(function (res) {
            if (res.data.success) {
                return res.data;
            }
            return $q.reject(res.data);
        }, function (res) {
            if (res.data.slice) {
                res.data = {success: false, message: res.data};
            } else {
                if (!res.data.hasOwnProperty("message")) {
                    res.data.message = 'Error ' + res.status + ': ' + res.data.toString();
                }
                if (!res.data.hasOwnProperty("success")) {
                    res.data.success = false;
                }
            }
            return $q.reject(res.data);
        });
    };

    angrdata.redeemToken = function (token) {
        var fireTokenQuery = function () {
            return $http.get('/api/tokens/' + token).then(function (res) {
                if (res.data.ready) {
                    return res.data.value;
                }
                return $timeout(fireTokenQuery, 1000);
            }, function () {
                alert('Oh jeez something went wrong');
            });
        };
        return fireTokenQuery();
    };

    angrdata.newProject = function (project) {
        var config = {
            url: '/api/projects/new',
            method: 'POST',
            headers: {
                'Content-Type': undefined
            },
            data: (function () {
                var formData = new window.FormData();
                formData.append('metadata', JSON.stringify(project));
                formData.append('file', project.file);
                return formData;
            }()),
            transformRequest: function (formData) { return formData; }
        };

        return genericRequest(config);
    };

    angrdata.connectProject = function (hostname, port) {
        var config = POST('/api/instances/connect', {hostname: hostname, port: parseInt(port, 10)});
        return genericRequest(config);
    };

    angrdata.constructBasicCFG = function () {
        if (angrdata.gcomm.cfgReady) {
            return genEmptyPromise();
        }
        return $http.get('/api/instances/' + angrdata.gcomm.instance + '/constructCFG').then(function (res) {
            if (res.data.hasOwnProperty('token')) {
                return angrdata.redeemToken(res.data.token).then(function (res) {
                    angrdata.gcomm.cfgReady = true;
                    return res.data;
                });
            }
            angrdata.gcomm.cfgReady = true;
            return res.data;
        });
    };

    angrdata.loadFunctionManager = function () {
        if (angrdata.gcomm.funcMan.loaded) {
            return genEmptyPromise();
        }
        return angrdata.constructBasicCFG().then(function () {
            var config = GET('/api/instances/' + angrdata.gcomm.instance + '/functionManager');
            return genericRequest(config).then(function (data) {
                angrdata.gcomm.funcMan.functions = data.data.functions;
                angrdata.gcomm.funcMan.edges = data.data.edges;
                angrdata.gcomm.funcMan.loaded = true;
            });
        });
    };

    angrdata.renameFunction = function (func) {
        var config = POST('/api/instances/' + angrdata.gcomm.instance + '/functions/' + func.address + '/rename', func.name);
        return genericRequest(config);
    };

    angrdata.neededIRSBs = function (func) {
        var need = [], i;
        for (i = 0; i < func.blocks.length; i += 1) {
            if (!angrdata.gcomm.irsbs.hasOwnProperty(func.blocks[i]) &&
                    !angrdata.gcomm.simProcedureSpots.hasOwnProperty(func.blocks[i])) {
                need.push(func.blocks[i]);
            }
        }
        return need;
    };

    angrdata.loadIRSBs = function (func) {
        var need = angrdata.neededIRSBs(func), config;
        if (need.length === 0) {
            return genEmptyPromise();
        }

        config = POST('/api/instances/' + angrdata.gcomm.instance + '/irsbs', need);
        return genericRequest(config).then(function (data) {
            var fields = ['irsbs', 'simProcedureSpots', 'simProcedures', 'disasm'],
                fieldkey,
                field,
                i;
            for (fieldkey = 0; fieldkey < fields.length; fieldkey += 1) {
                field = fields[fieldkey];
                if (data.data.hasOwnProperty(field)) {
                    for (i in data.data[field]) {
                        if (data.data[field].hasOwnProperty(i)) {
                            angrdata.gcomm[field][i] = data.data[field][i];
                        }
                    }
                }
            }
        });
    };

    addSurveyor = function (surveyor) {
        var paths = surveyor.path_data, i, split;
        delete surveyor.path_data;
        angrdata.gcomm.surveyors[surveyor.id] = surveyor;
        for (i = 0; i < paths.length; i += 1) {
            paths[i].split = false;
            addPath(paths[i]);
        }
        for (split in surveyor.split_paths) {
            if (surveyor.split_paths.hasOwnProperty(split)) {
                addPath({split: true, children: surveyor.split_paths[split], id: split});
            }
        }
        surveyor.all_paths = [];
        Object.keys(surveyor.path_lists).forEach(function(pl) {
            var paths = surveyor.path_lists[pl];
            paths.forEach(function(p) { surveyor.all_paths.push(p); });
        });
    };

    addPath = function (path) {
        angrdata.gcomm.paths[path.id] = path;
    };

    angrdata.loadSurveyors = function () {
        if (angrdata.gcomm.surveyors !== null) {
            return genEmptyPromise();
        }
        angrdata.gcomm.surveyors = {};

        var config = GET('/api/instances/' + angrdata.gcomm.instance + '/surveyors');
        return genericRequest(config).then(function (data) {
            var i;
            for (i = 0; i < data.data.length; i += 1) {
                addSurveyor(data.data[i]);
            }
        });
    };

    angrdata.loadPaths = function () {
        var config = GET('/api/instances/' + angrdata.gcomm.instance + '/explore/paths');
        return genericRequest(config).then(function (data) {
            for (var prop in data.data) {
                if (data.data.hasOwnProperty(prop)) {
                    data.data[prop].forEach(addPath);
                }
            }
            return data;
        });
    };

    angrdata.newPath = function (arg) {
        var config = POST('/api/instances/' + angrdata.gcomm.instance + '/explore/paths', arg);
        return genericRequest(config).then(function (data) {
            var path = data.data;
            addPath(path);
            return path;
        });
    };

    angrdata.newSurveyor = function (surveyor) {
        var config = POST('/api/instances/' + angrdata.gcomm.instance + '/surveyors/new', {kwargs: surveyor});

        return genericRequest(config).then(function (data) {
            addSurveyor(data.data);
            return data;
        });
    };

    angrdata.findExprVal = function (sid, pid, data) {
        var config = POST('/api/instances/' + angrdata.gcomm.instance + '/surveyors/' + sid + '/paths/' + pid + '/expr_val', data);

        return genericRequest(config);
    };

    angrdata.stepPath = function (path_id, steps) {
        var config = POST('/api/instances/' + angrdata.gcomm.instance + '/explore/paths/' + path_id + '/step', {steps: steps});

        return genericRequest(config).then(function (data) {
            data.data.forEach(addPath);
            return data.data;
        });
    };

    angrdata.pathResume = function (sid, pid) {
        var config = POST('/api/instances/' + angrdata.gcomm.instance + '/surveyors/' + sid + '/resume/' + pid, {});

        return genericRequest(config).then(function (data) {
            addSurveyor(data.data);
        });
    };

    angrdata.pathSuspend = function (sid, pid) {
        var config = POST('/api/instances/' + angrdata.gcomm.instance + '/surveyors/' + sid + '/suspend/' + pid, {});

        return genericRequest(config).then(function (data) {
            addSurveyor(data.data);
        });
    };

    angrdata.pathGetState = function(pid) {
        var config = GET('/api/instances/' + angrdata.gcomm.instance + '/explore/paths/' + pid + '/state');

        return genericRequest(config).then(function(data) {
            return anaLoad(data.data.value, data.data.objects);
        });
    };

    return angrdata;
});

tools.factory('defaultError', function () {
    return function (data) {
        alert(data.message);
    };
});
