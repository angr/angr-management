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
    }
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

tools.factory('AngrData', function ($http, globalCommunicator) {
    var public = {};
    public.gcomm = globalCommunicator;

    var defaultAlert = function (f) {
        if (typeof f === 'function') {
            return f;
        } else {
            return function (data) {
                alert(data.message);
            };
        }
    };

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

    var genericRequest = function (config, callback, error) {
        error = defaultAlert(error);
        $http(config).success(function(data) {
            if (data.success) {
                callback(data);
            } else {
                error(data);
            }
        }).error(function(data, status) {
            if (data.slice) {
                data = {success: false, message: data};
            } else {
                if (!("message" in data)) {
                    data.message = 'Error ' + status + ': ' + data.toString();
                }
                if (!("success" in data)) {
                    data.success = false;
                }
            }
            error(data);
        });
    };

    public.redeemToken = function (token, callback) {
        var fireTokenQuery = function() {
            $http.get('/api/tokens/' + token).success(function(res) {
                if (res.ready) {
                    callback(res.value);
                } else {
                    fireTokenQuery();
                }
            }).error(function() {
                alert('Oh jeez something went wrong');
            });
        };
        fireTokenQuery();
    };

    public.newProject = function (project, callback, error) {
        error = defaultAlert(error);
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

        genericRequest(config, callback, error);
    };

    public.connectProject = function (hostname, port, callback, error) {
        var config = POST('/api/instances/connect', {hostname: hostname, port: port - 0});
        genericRequest(config, callback, error);
    };

    public.constructBasicCFG = function (callback, error) {
        if (public.gcomm.cfgReady) {
            callback();
        } else {
            $http.get('/api/instances/' + public.gcomm.instance + '/constructCFG').success(function (data) {
                if ('token' in data) {
                    public.redeemToken(data.token, function (data) {
                        public.gcomm.cfgReady = true;
                        callback(data);   
                    }, error);
                } else {
                    public.gcomm.cfgReady = true;
                    callback(data);
                }
            }).error(error);
        }
    };

    public.loadFunctionManager = function (callback, error) {
        if (public.gcomm.funcMan.loaded) {
            callback();
        } else {
            public.constructBasicCFG(function () {
                var config = GET('/api/instances/' + public.gcomm.instance + '/functionManager');
                genericRequest(config, function (data) {
                    public.gcomm.funcMan.functions = data.data.functions;
                    public.gcomm.funcMan.edges = data.data.edges;
                    public.gcomm.funcMan.loaded = true;
                    callback();
                }, error);
            }, error);
        }
    };

    public.renameFunction = function (func, callback, error) {
        var config = POST('/api/instances/' + public.gcomm.instance + '/functions/' + func.address + '/rename', func.name);
        genericRequest(config, callback, error);
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

    public.loadIRSBs = function (func, callback, error) {
        var need = public.neededIRSBs(func);
        if (need.length == 0) {
            callback();
            return;
        }

        var config = POST('/api/instances/' + public.gcomm.instance + '/irsbs', need);
        genericRequest(config, function (data) {
            var fields = ['irsbs', 'simProcedureSpots', 'simProcedures', 'disasm'];
            for (var fieldkey = 0; fieldkey < fields.length; fieldkey++) {
                var field = fields[fieldkey];
                if (field in data.data) {
                    for (var i in data.data[field]) {
                        public.gcomm[field][i] = data.data[field][i];
                    }
                }
            }
            callback();
        }, error);
    };

    public.loadSurveyors = function (callback, error) {
        if (public.gcomm.surveyors.length > 0) {
            callback();
        }

        var config = GET('/api/instances/' + public.gcomm.instance + '/surveyors');
        genericRequest(config, function (data) {
            public.gcomm.surveyors = data.data;
            callback();
        }, error);
    };

    public.newSurveyor = function (surveyor, callback, error) {
        var config = POST('/api/instances/' + public.gcomm.instance + '/surveyors/new', {kwargs: surveyor});

        genericRequest(config, function (data) {
            public.gcomm.surveyors.push(data.data);
            callback(data);
        }, error);
    };

    return public;
});
