var tools = angular.module('angr.tools', []);

tools.directive('onEnter', function() {
    return function(scope, element, attrs) {
        element.bind("keydown keypress", function(event) {
            if(event.which === 13) {
                scope.$apply(function(){
                    scope.$eval(attrs.onEnter, {'event': event});
                });

                event.preventDefault();
            }
        });
    };
});

tools.directive('realClick', function() {
    return function(scope, element, attrs) {
        var sx = 0;
        var sy = 0;
        var funcExpr = attrs.realClick;
        element.bind("mousedown", function(e) {
            sx = e.pageX;
            sy = e.pageY;
        });

        element.bind("mouseup", function (e) {
            var dx = Math.abs(sx - e.pageX);
            var dy = Math.abs(sy - e.pageY);
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
            var x = 'sub_' + parseInt(func.address.toString()).toString(16);
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
            x = 'sub_' + parseInt(func.address.toString()).toString(16);
        } else {
            x = func.name;
        }
        return x + ' (0x' + parseInt(func.address.toString()).toString(16) + ')';
    };
});

tools.filter('hexpad', function (AngrData) {
    return function (str) {     // Accounts for decimal strings, ew
        var x = parseInt(str.toString()).toString(16);
        while (x.length < 8) { // TODO: less hax
            x = '0' + x;
        }
        return x;
    };
});

tools.filter('hex', function () {
    return function (str) {     // Accounts for decimal strings, ew
        return parseInt(str.toString()).toString(16);
    };
});

// Okay here's the big one

tools.factory('AngrData', function ($q, $http, $timeout, globalCommunicator) {
    var public = {};
    public.gcomm = globalCommunicator;

    var GET = function (url) {
        return {
            method: 'GET',
            url: url
        };
    };

    var POST = function (url, data) {
        return {
            method: 'POST',
            url: url,
            data: data
        };
    };

    var genEmptyPromise = function() { // haha
        var deferred = $q.defer();
        deferred.resolve();
        return deferred.promise;
    };

    var genericRequest = function (config) {
        return $http(config).then(function(res) {
            if (res.data.success) {
                return res.data;
            } else {
                return $q.reject(res.data);
            }
        }, function(res) {
            if (res.data.slice) {
                res.data = {success: false, message: data};
            } else {
                if (!("message" in res.data)) {
                    res.data.message = 'Error ' + res.status + ': ' + res.data.toString();
                }
                if (!("success" in res.data)) {
                    res.data.success = false;
                }
            }
            return $q.reject(res.data);
        });
    };

    public.redeemToken = function (token) {
        var fireTokenQuery = function() {
            return $http.get('/api/tokens/' + token).then(function(res) {
                if (res.data.ready) {
                    return res.data.value;
                } else {
                    return $timeout(fireTokenQuery, 1000);
                }
            }, function() {
                alert('Oh jeez something went wrong');
            });
        };
        return fireTokenQuery();
    };

    public.newProject = function (project) {
        var config = {
            url: '/api/projects/new',
            method: 'POST',
            headers: {
                'Content-Type': undefined
            },
            data: (function() {
                var formData = new FormData();
                formData.append('metadata', JSON.stringify(project));
                formData.append('file', project.file);
                return formData;
            })(),
            transformRequest: function(formData) { return formData; }
        };

        return genericRequest(config);
    };

    public.connectProject = function (hostname, port) {
        var config = POST('/api/instances/connect', {hostname: hostname, port: port - 0});
        return genericRequest(config);
    };

    public.constructBasicCFG = function () {
        if (public.gcomm.cfgReady) {
            return genEmptyPromise();
        } else {
            return $http.get('/api/instances/' + public.gcomm.instance + '/constructCFG').then(function (res) {
                if ('token' in res.data) {
                    return public.redeemToken(res.data.token).then(function (res) {
                        public.gcomm.cfgReady = true;
                        return res.data;
                    });
                } else {
                    public.gcomm.cfgReady = true;
                    return res.data;
                }
            });
        }
    };

    public.loadFunctionManager = function () {
        if (public.gcomm.funcMan.loaded) {
            return genEmptyPromise();
        } else {
            return public.constructBasicCFG().then(function () {
                var config = GET('/api/instances/' + public.gcomm.instance + '/functionManager');
                return genericRequest(config).then(function (data) {
                    public.gcomm.funcMan.functions = data.data.functions;
                    public.gcomm.funcMan.edges = data.data.edges;
                    public.gcomm.funcMan.loaded = true;
                });
            });
        }
    };

    public.renameFunction = function (func) {
        var config = POST('/api/instances/' + public.gcomm.instance + '/functions/' + func.address + '/rename', func.name);
        return genericRequest(config);
    };

    public.neededIRSBs = function (func) {
        var need = [];
        for (var i = 0; i < func.blocks.length; i++) {
            if (!(func.blocks[i] in public.gcomm.irsbs) && !(func.blocks[i] in public.gcomm.simProcedureSpots)) {
                need.push(func.blocks[i]);
            }
        }
        return need;
    };

    public.loadIRSBs = function (func) {
        var need = public.neededIRSBs(func);
        if (need.length === 0) {
            return genEmptyPromise();
        }

        var config = POST('/api/instances/' + public.gcomm.instance + '/irsbs', need);
        return genericRequest(config).then(function (data) {
            var fields = ['irsbs', 'simProcedureSpots', 'simProcedures', 'disasm'];
            for (var fieldkey = 0; fieldkey < fields.length; fieldkey++) {
                var field = fields[fieldkey];
                if (field in data.data) {
                    for (var i in data.data[field]) {
                        public.gcomm[field][i] = data.data[field][i];
                    }
                }
            }
        });
    };

    var addSurveyor = function (surveyor) {
        var paths = surveyor.path_data;
        delete surveyor.path_data;
        public.gcomm.surveyors[surveyor.id] = surveyor;
        for (var i = 0; i < paths.length; i++) {
            paths[i].split = false;
            addPath(paths[i]);
        }
        for (var split in surveyor.split_paths) {
            addPath({split: true, children: surveyor.split_paths[split], id: split});
        }
    };

    var addPath = function (path) {
        public.gcomm.paths[path.id] = path;
    };

    public.loadSurveyors = function () {
        if (public.gcomm.surveyors !== null) {
            return genEmptyPromise();
        }
        public.gcomm.surveyors = {};

        var config = GET('/api/instances/' + public.gcomm.instance + '/surveyors');
        return genericRequest(config).then(function (data) {
            for (var i = 0; i < data.data.length; i++) {
                addSurveyor(data.data[i]);
            }
        });
    };

    public.newSurveyor = function (surveyor) {
        var config = POST('/api/instances/' + public.gcomm.instance + '/surveyors/new', {kwargs: surveyor});

        return genericRequest(config).then(function (data) {
            addSurveyor(data.data);
            return data;
        });
    };

    public.surveyorStep = function (surveyor, steps) {
        var config = POST('/api/instances/' + public.gcomm.instance + '/surveyors/' + surveyor + '/step', {steps: steps});

        return genericRequest(config).then(function (data) {
            addSurveyor(data.data);
        });
    };

    public.pathResume = function (sid, pid) {
        var config = POST('/api/instances/' + public.gcomm.instance + '/surveyors/' + sid + '/resume/' + pid, {});

        return genericRequest(config).then(function (data) {
            addSurveyor(data.data);
        });
    };

    public.pathSuspend = function (sid, pid) {
        var config = POST('/api/instances/' + public.gcomm.instance + '/surveyors/' + sid + '/suspend/' + pid, {});

        return genericRequest(config).then(function (data) {
            addSurveyor(data.data);
        });
    };

    return public;
});

tools.factory('defaultError', function() {
    return function(data) {
        alert(data.message);
    };
});
