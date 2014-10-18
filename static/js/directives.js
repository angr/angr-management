'use strict';

var dirs = angular.module('angr.directives', ['angr.filters', 'angr.view', 'angr.contextMenu']);
dirs.directive('newproject', function() {
    return {
        templateUrl: '/static/partials/newproject.html',
        restrict: 'AE',
        scope: {
            projects: '='
        },
        controller: function($scope, $http) {
            $scope.project = {};
            $scope.project.name = "";
            $scope.project.file = null;
            $scope.create = function() {
                var config = {
                    url: '/api/projects/new',
                    method: 'POST',
                    headers: {
                        'Content-Type': undefined
                    },
                    data: (function() {
                        var formData = new FormData();
                        formData.append('metadata', JSON.stringify($scope.project));
                        formData.append('file', $scope.project.file);
                        return formData;
                    })(),
                    transformRequest: function(formData) { return formData; }
                };
                $http(config).success(function(data) {
                    if (data.success) {
                        alert('project created!');
                        $scope.projects.push({
                            name: data.name,
                            instances: []
                        });
                        $scope.project.file = null;
                        $scope.project.name = "";
                    } else {
                        alert(data.message);
                    }
                }).error(function() {
                    alert('could not create project :(');
                });
            };
        }
    };
});

dirs.directive('useproject', function () {
    return {
        template: '<a ng-click="clicky()">{{project.name}}</a>',
        restrict: 'AE',
        scope: {
            project: '='
        },
        controller: function ($scope, $modal) {
            $scope.clicky = function () {
                $modal.open({
                    templateUrl: '/static/partials/useproject.html',
                    scope: $scope,
                    controller: 'UseProjectDialog'
                });
            };
        }
    }
});

dirs.directive('connectproject', function ($http, $location) {
    return {
        templateUrl: '/static/partials/connectproject.html',
        restrict: 'AE',
        controller: function ($scope) {
            $scope.hostname = 'localhost';
            $scope.port = '1234';
            $scope.thinking = false;
            $scope.connect = function () {
                if (Math.floor($scope.port - 0).toString() == $scope.port) {
                    $scope.thinking = true;
                    $http.post('/api/instances/connect', {hostname: $scope.hostname, port: $scope.port - 0}).success(function (data) {
                        $scope.thinking = false;
                        if (data.success) {
                            $location.path('/instance/' + data.id);
                        } else {
                            alert(data.message);
                        }
                    }).error(function () {
                        $scope.thinking = false;
                        alert("Couldn't connect for some reason...");
                    });
                } else {
                    alert('Enter a valid port please!');
                }
            };
        }
    };
});



dirs.directive('loadfile', function($http) {
    return {
        templateUrl: '/static/partials/loadfile.html',
        restrict: 'A',
        scope: {
            file: '=',
        },
        link: function($scope, element, attrs) {
            $scope.url = {chosenURL: ''};
            $scope.uploadURL = function() {
                var url = $scope.url.chosenURL;
                if (url.indexOf("http://") === 0) {
                    url = url.slice(7);
                } else if (url.indexOf("https://") === 0) {
                    url = url.slice(8);
                } else {
                    return;
                }
                $http({
                    method: 'GET',
                    url: "http://www.corsproxy.com/" + url,
                    responseType: "blob",
                    transformResponse: function(data) { return data; }
                }).success(function(data) {
                    $scope.file = data;
                });
            };

            var blankHandler = function(e) {
                e.preventDefault();
                e.stopPropagation();
                return false;
            };

            var highlightDrop = function(e) {
                element.addClass('dragover');
                return blankHandler(e);
            };

            var cautiousUnhighlight = function (e) {
                var rect = e.target.getBoundingClientRect();
                if (e.target != element[0]) return blankHandler(e);
                if (e.clientX > rect.left && e.clientX < rect.right && e.clientY > rect.top && e.clientY < rect.bottom) return blankHandler(e);
                return unhighlightDrop(e);
            };

            var unhighlightDrop = function(e) {
                element.removeClass('dragover');
                return blankHandler(e);
            };

            element.bind('dragover', blankHandler);
            element.bind('dragenter', highlightDrop);
            element.bind('dragleave', cautiousUnhighlight);
            element.bind('dragend', unhighlightDrop);

            element.bind('drop', function(event) {
                element.removeClass('dragover');
                event.preventDefault();
                var file = event.dataTransfer.files[0];

                var reader = new FileReader();
                reader.onload = function(e) {
                    $scope.$apply(function() {
                        $scope.file = new Blob([e.target.result]);
                    });
                };
                reader.readAsArrayBuffer(file);

                return false;
            });
        }
    };
});

dirs.directive('viewlayout', function (RecursionHelper) {
    return {
        templateUrl: '/static/partials/viewlayout.html',
        restrict: 'AE',
        scope: {
            view: '=',
            instance: '='
        },  // no controller because #swag
        compile: RecursionHelper.compile
    };
});

dirs.directive('bblock', function(ContextMenu) {
    return {
        priority: 100,
        templateUrl: '/static/partials/bblock.html',
        restrict: 'AE',
        scope: {
            block: '=',
            showDetails: '=',
            view: '='
        },
        controller: function($scope, $element) {
            if ($scope.block.type === 'IRSB') {
                $scope.text = '0x' + $scope.block.addr.toString(16);
            } else if ($scope.block.type === 'proc') {
                $scope.text = $scope.block.name;
            }
            if ($scope.block.color) {
                $element.parent().css('background-color', $scope.block.color);
            }
        },
        link: function ($scope, element, attrs) {
            ContextMenu.registerEntries(element, function () {
                return [
                    {
                        text: 'Basic block actions',
                        subitems: [
                            {
                                text: 'Find paths to here'
                            }, {
                                text: 'Reanalyze'
                            }
                        ]
                    }
                ];
            });
        }
    };
});

dirs.directive('graph', function(ContextMenu) {
    return {
        templateUrl: '/static/partials/graph.html',
        restrict: 'AE',
        scope: {
            nodes: '=',
            edges: '=',
            view: '=',
            nodeType: '='
        },
        controller: function($scope, $element, Schedule) {
            jsPlumb.Defaults.MaxConnections = 10000;
            $scope.plumb = jsPlumb.getInstance({
                ConnectionOverlays: [
                    ["Arrow", {location: 1}]
                ]
            });

            var entryEndpoint = {
                maxConnections: 10000000,
                isTarget: true
            };
            var exitEndpoint = {
                maxConnections: 10000000,
                connector:[ "Flowchart", { stub:[40, 60], gap:10, cornerRadius:5, alwaysRespectStubs:true } ],
            };

            var GRID_SIZE = 20;
            var HEADER = 160;

            $scope.layout = function() {
                var g = new graphlib.Graph()
                    .setGraph({ nodesep: 200, edgesep: 200, ranksep: 100 })
                    .setDefaultEdgeLabel(function() { return {}; });
                jQuery($($element).find('#graphRoot')).children('div').each(function(i, e) {
                    var $e = jQuery(e);
                    var id = $e.attr('id');
                    if (typeof id === 'undefined') return;
                    g.setNode(id, {width: $e.width(), height: $e.height()});
                });
                for (var i in $scope.edges) {
                    var edge = $scope.edges[i];
                    g.setEdge(edge.from.toString(), edge.to.toString());
                }
                dagre.layout(g);
                g.nodes().forEach(function(id) {
                    var data = g.node(id);
                    var $e = jQuery('#' + id);
                    var roundedCenterX = HEADER + GRID_SIZE * Math.round(data.x/GRID_SIZE);
                    var roundedCenterY = HEADER + GRID_SIZE * Math.round(data.y/GRID_SIZE);
                    $e.css('left', roundedCenterX - data.width/2);
                    $e.css('top', roundedCenterY - data.height/2);
                });
                $scope.plumb.repaintEverything();
            };

            // Tell JS to queue (timeout at zero seconds) this init routine
            // It needs to run later, after angular has finished processing shit
            // and has parsed the ng-ifs and ng-repeats
            Schedule(function() {
                var graphRoot = jQuery($element).find('#graphRoot');
                $scope.plumb.setContainer(graphRoot);
                graphRoot.children('div').each(function(i, e) {
                    var $e = jQuery(e);
                    $scope.plumb.draggable($e, {grid: [GRID_SIZE, GRID_SIZE]});
                    $scope.plumb.addEndpoint(e.id, entryEndpoint, {anchor: 'TopCenter', uuid: e.id + '-entry'});
                    $scope.plumb.addEndpoint(e.id, exitEndpoint, {anchor: ['Continuous', {faces: ['bottom']}], uuid: e.id + '-exit'});
                });

                for (var i in $scope.edges) {
                    var edge = $scope.edges[i];
                    $scope.plumb.connect({
                        uuids: [edge.from + '-exit', edge.to + '-entry'],
                        detachable: false,
                    });
                }

                Schedule($scope.layout);
            });

            $scope.$watch('nodes', function (nv, ov) {
                Schedule($scope.layout);
            }, true);
        }
    };
});

dirs.directive('cfg', function(ContextMenu, AngrToken) {
    return {
        templateUrl: '/static/partials/cfg.html',
        restrict: 'AE',
        scope: {
            instance: '=',
            view: '='
        },
        controller: function($scope, $http, $interval) {
            var handleCFG = function(data) {
                $scope.view.data.rawCFGData = data;
                $scope.view.data.loaded = true;

                var blockToColor = {};
                $scope.view.data.colors = randomColor({
                        count: Object.keys(data.functions).length,
                        luminosity: 'light'});
                var i = 0;
                $scope.functions = {};
                for (var addr in data.functions) {
                    var blocks = data.functions[addr];
                    $scope.functions[addr] = { blocks: blocks };
                    for (var j in blocks) {
                        blockToColor[blocks[j]] = $scope.view.data.colors[i];
                    }
                    i += 1;
                }
                $scope.view.data.cfgNodes = {};
                for (var i in data.nodes) {
                    var node = data.nodes[i];
                    var id = node.type + (node.type === 'IRSB' ? node.addr : node.name);
                    if (node.addr) {
                        node.color = blockToColor[node.addr];
                    }
                    $scope.view.data.cfgNodes[id] = node;
                }
                $scope.view.data.cfgEdges = [];
                for (var i in data.edges) {
                    var edge = data.edges[i];
                    var fromId = edge.from.type + (edge.from.type === 'IRSB' ? edge.from.addr : edge.from.name);
                    var toId = edge.to.type + (edge.to.type === 'IRSB' ? edge.to.addr : edge.to.name);
                    $scope.view.data.cfgEdges.push({from: fromId, to: toId});
                }
            };

            if (!$scope.view.data.loaded) {
                $scope.view.data.loaded = false;
                $http.get('/api/instances/' + $scope.instance + '/cfg').success(function(data) {
                    if ('token' in data) {
                        AngrToken.redeem(data.token, handleCFG);
                    } else {
                        handleCFG(data);
                    }
                });
            }
        },
        link: function ($scope, element, attrs) {
            ContextMenu.registerEntries(element, function () {
                return [
                    {
                        text: 'CFG Actions',
                        subitems: [
                            {
                                text: 'CFG Scope',
                                subitems: [
                                    {
                                        text: 'Interprocedure',
                                        checked: true
                                    }, {
                                        text: 'Function'
                                    }, {
                                        text: 'Proximity'
                                    }
                                ]
                            }, {
                                text: 'Crash and blame fish'
                            }
                        ]
                    }
                ]
            });
        }
    };
});

dirs.directive('funcpicker', function(AngrToken) {
    return {
        templateUrl: '/static/partials/funcpicker.html',
        restrict: 'AE',
        scope: {
            instance: '=',
            view: '='
        },
        controller: function($scope, $http) {
            $scope.console = console;
            if (!$scope.view.data.loaded) {
                $scope.view.data.loaded = false;
                $http.get('/api/instances/' + $scope.instance + '/functions')
                    .success(function(data) {
                        if ('token' in data) {
                            AngrToken.redeem(data.token, handleFuncMan);
                        } else {
                            handleFuncMan(data);
                        }
                    });
            }

            $scope.click = function (func) {
                $scope.view.comm.funcMan.selected = func;
            };

            var handleFuncMan = function (data) {
                $scope.view.comm.funcMan.selected = null;
                // Hate.
                for (var key in data.functions) {
                    if (!data.functions.hasOwnProperty(key)) continue;
                    $scope.view.comm.funcMan.functions[parseInt(key)] = data.functions[key];
                }
                $scope.view.comm.funcMan.edges = data.edges;
                $scope.view.comm.funcMan.loaded = true;
                $scope.view.data.loaded = true;
            };
        }
    };
});

dirs.directive('funcman', function () {
    return {
        templateUrl: '/static/partials/funcman.html',
        restrict: 'AE',
        scope: {
            instance: '=',
            view: '='
        },
        controller: function ($scope, $http) {
            $scope.scopeBreak = {
                newName: ''
            };
            $scope.hasData = false;
            $scope.rename = function() {
                var f = $scope.view.comm.funcMan.selected;
                f.name = $scope.scopeBreak.newName;
                $http.post('/api/instances/' + $scope.instance + '/functions/' + f.address + '/rename', f.name);
            };
            $scope.$watch('view.comm.funcMan.selected', function(sf) {
                if (!sf) return;
                $scope.scopeBreak.newName = sf.name;
            });
            
        }
    };
});

dirs.directive('proxgraph', function ($timeout) {
    return {
        templateUrl: '/static/partials/proxgraph.html',
        restrict: 'AE',
        scope: {
            view: '=',
            instance: '='
        },
        controller: function ($scope, $element) {
            $scope.$watch('view.comm.funcMan.selected', function (nv) {
                if (nv == null) return;
                var elm = jQuery($element).find('#graphRoot').find('#' + nv.address.toString());

                var left = parseInt(elm[0].style.left);
                var width = elm[0].clientWidth;
                var clientWidth = $element[0].clientWidth;
                $element[0].scrollLeft = left + (width/2) - (clientWidth/2);

                var top = parseInt(elm[0].style.top);
                var height = elm[0].clientHeight;
                var clientHeight = $element[0].clientHeight;
                $element[0].scrollTop = top + (height/2) - (clientHeight/2);
            });
        }
    };
});

dirs.directive('funcnode', function () {
    return {
        templateUrl: '/static/partials/funcnode.html',
        restrict: 'AE',
        scope: {
            view: '=',
            node: '='
        },
        controller: function ($scope) {
            $scope.click = function () {
                $scope.view.comm.funcMan.selected = $scope.node;
            };
        }
    };
});

dirs.directive('surveyors', function($http) {
    return {
        templateUrl: '/static/partials/surveyors.html',
        restrict: 'AE',
        scope: { instance: '=' },
        controller: function($scope, $http) {

            $scope.surveyors = [ ];
            $http.get("/api/instances/" + $scope.instance + "/surveyors").success(function(data, status) {
                $scope.surveyors = data;
            });
        }
    }
});

dirs.directive('surveyor', function($http) {
    return {
        templateUrl: '/static/partials/surveyor.html',
        restrict: 'AE',
        scope: { sid: '=', instance: "=", surveyor: '=data' },
        controller: function($scope, $http)
        {
            $scope.show_surveyor = false;
            if ($scope.surveyor == undefined)
            {
                $http.get("/api/instances/" + $scope.instance + "/surveyors/" + $scope.sid).success(function(data, status) {
                    $scope.surveyor = data;
                });
            }

            $scope.steps = 1;
            $scope.step = function(steps) {
                $http.post("/api/instances/" + $scope.instance + "/surveyors/" + $scope.sid + "/step", {steps: steps}).success(function(data, status) {
                    $scope.surveyor = data;
                });
            }

            $scope.reactivate = function(path) {
                $http.post("/api/instances/" + $scope.instance + "/surveyors/" + $scope.sid + "/resume/" + path.id).success(function(data, status) {
                    $scope.surveyor = data;
                });
            }

            $scope.suspend = function(path) {
                $http.post("/api/instances/" + $scope.instance + "/surveyors/" + $scope.sid + "/suspend/" + path.id).success(function(data, status) {
                    $scope.surveyor = data;
                });
            }
        }
    }
});

dirs.directive('path', function($http) {
    return {
        templateUrl: '/static/partials/path.html',
        restrict: 'AE',
        scope: { path: '=data' },
        controller: function($scope, $http)
        {
            $scope.show_path = true;
            $scope.show_events = false;
            $scope.show_backtrace = false;
            $scope.event_limit = 10;
            $scope.backtrace_limit = 10;
        }
    }
});

dirs.directive('event', function($http) {
    return {
        templateUrl: '/static/partials/path_event.html',
        restrict: 'AE',
        scope: { event: '=data' },
        controller: function($scope, $http)
        {
            $scope.show_refs = false;
            $scope.show_event = false;
        }
    }
});

dirs.directive('address', function($http) {
    return {
        templateUrl: '/static/partials/address.html',
        restrict: 'AE',
        scope: { address: '=a' },
        controller: function($scope, $http)
        {
            $scope.isNaN = isNaN;
        }
    }
});

dirs.directive('ref', function($http) {
    return {
        templateUrl: '/static/partials/ref.html',
        restrict: 'AE',
        scope: { ref: '=data' },
        controller: function($scope, $http)
        {
        }
    }
});

dirs.directive('irsb', function() {
    return {
        templateUrl: '/static/partials/irsb.html',
        restrict: 'E',
        scope: {
            irsb: '=data',
            view: '='
        },
        controller: function($scope) {

        },
    };
});

dirs.directive('irstmt', function() {
    return {
        templateUrl: '/static/partials/irstmt.html',
        restrict: 'E',
        scope: {
            stmt: '=',
            view: '='
        },
    };
});

dirs.directive('irexpr', function(RecursionHelper) {
    return {
        templateUrl: '/static/partials/irexpr.html',
        restrict: 'E',
        scope: {
            expr: '=',
            view: '='
        },
        compile: RecursionHelper.compile,
    };
});

dirs.directive('cexpr', function(RecursionHelper, $http) {
    return {
        templateUrl: '/static/partials/cexpr.html',
        restrict: 'E',
        scope: {
            expr: '=',
            parens: '=',
            view: '='
        },
        compile: RecursionHelper.compile,
        controller: function($scope, $http) {
            $scope.show_solve = false;
            $scope.num_solutions = 1;

            $scope.solutions = function(n) {
                //$http.get("/api/projects/" + $scope.project.name + "/surveyors/" + $scope.sid + "/paths/" + expr.path_id + "/solve" ).success(function(data, status) {
            }

            $scope.max_solution = function(n) {
            }

            $scope.min_solution = function(n) {
            }

            $scope.get_type = function(o) {
                if ($scope.expr == null || $scope.expr == undefined) return 'null';
                else if (typeof $scope.expr == "boolean") return 'boolean';
                else if (!isNaN($scope.expr)) return 'integer';
            }
        }
    };
});

dirs.directive('cast', function(RecursionHelper) {
    return {
        templateUrl: '/static/partials/cast.html',
        restrict: 'E',
        scope: {
            ast: '=',
            parens: '=',
            view: '='
        },
        compile: RecursionHelper.compile,
        controller: function($scope, $http) {
            $scope.ops = {
                __add__: "+", __sub__: "-", __div__: "/", __truediv__: "/", __mul__: "*", __mod__: "%",
                __eq__: "==", __ne__: "!=", __ge__: ">=", __gt__: ">", __le__: "<=", __lt__: "<",
                __neg__: "-", __or__: "|", __and__: "&", __xor__: "^", __invert__: "~",
                __lshift__: "<<", __rshift__: ">>"
            }
        }
    };
});

dirs.directive('irtmp', function(ContextMenu) {
    return {
        templateUrl: '/static/partials/irtmp.html',
        restrict: 'E',
        scope: {
            tmp: '=',
            view: '='
        },
        controller: function ($scope) {
            $scope.mouse = function (over) {
                $scope.view.comm.cfgHighlight.tmps[$scope.tmp] = over;
            };
        },
        link: function ($scope, element, attrs) {
            ContextMenu.registerEntries(element, function () {
                return [
                    {
                        text: 'Temp actions',
                        subitems: [
                            {
                                text: 'Rename temp'
                            }, {
                                text: 'wait no that\'s stupid',
                                disabled: true
                            }, {
                                text: 'why would you do that',
                                disabled: true
                            }
                        ]
                    }
                ];
            });
        }
    };
});

dirs.directive('irreg', function(ContextMenu) {
    return {
        templateUrl: '/static/partials/irreg.html',
        restrict: 'E',
        scope: {
            offset: '=',
            size: '=',
            operation: '=',
            view: '='
        },
        controller: function ($scope) {
            $scope.mouse = function (over) {
                $scope.view.comm.cfgHighlight.registers[$scope.offset] = over;
            };
        },
        link: function ($scope, element, attrs) {
            $scope.stupidcount = 0;
            ContextMenu.registerEntries(element, function () {
                $scope.stupidcount++;
                var stupidtext = $scope.stupidcount.toString();
                if ($scope.stupidcount % 100 < 20 && $scope.stupidcount % 100 > 10) {
                    stupidtext += 'th';
                } else {
                    if ($scope.stupidcount % 10 == 1) {
                        stupidtext += 'st';
                    } else if ($scope.stupidcount % 10 == 2) {
                        stupidtext += 'nd';
                    } else if ($scope.stupidcount % 10 == 3) {
                        stupidtext += 'rd';
                    } else {
                        stupidtext += 'th';
                    }
                }
                return [
                    {
                        text: 'Register actions',
                        subitems: [
                            {
                                text: 'Rename register'
                            }, {
                                text: 'Trace data sources'
                            }, {
                                text: 'Appreciate offset ' + $scope.offset,
                                subitems: [
                                    {
                                        text: 'Appreciate the fact that this is the ' + stupidtext + ' time you\'ve opened this dialog on this element and also that this is a really long message'
                                    }, {
                                        text: 'or not'
                                    }
                                ]
                            }
                        ]
                    }
                ];
            });
        }
    };
});

dirs.directive('splittest', function (View) {
    return {
        templateUrl: '/static/partials/splittest.html',
        restrict: 'AE',
        scope: {
            view: '='
        },
        controller: function ($scope, $element) {
            $scope.randColor = function () {
                $scope.view.data.color = randomColor({luminosity: 'bright'});
            };

            var split = function(horizontal) {
                $scope.view = $scope.view.split(new View({}, 'SPLITTEST'), horizontal, 0.5, true);
            };

            $scope.splitHorz = function () {
                split(true);
            };

            $scope.splitVert = function () {
                split(false);
            };
        }
    }
});

// John can make his own file if he wants to bitch about it

dirs.factory('AngrToken', function ($http) {
    var redeemToken = function (token, callback) {
        var fireTokenQuery = function() {
            $http.get('/api/tokens/' + token).success(function(res) {
                if (res.ready) {
                    callback(res.value);
                } else {
                    fireTokenQuery();
                }
            }).error(function() {
                // TODO: Bad
            });
        };
        fireTokenQuery();
    };
    return {redeem: redeemToken};
});

dirs.factory('Schedule', function ($timeout) {
    return function (callback) {
        $timeout(callback, 0);
    }
});

dirs.filter('funcname', function () {
    return function (func) {
        if (func.name === null) {
            return 'sub_' + parseInt(func.address.toString()).toString(16);
        } else {
            return func.name;    // ugh.
        }
    };
});

dirs.filter('funcnameextra', function () {
    return function (func) {
        var x;
        if (func.name === null) {
            x = 'sub_' + func.address.toString(16);
        } else {
            x = func.name;
        } 
        return x + ' (0x' + func.address.toString(16) + ')';
    };
});

dirs.filter('hex', function () {
    return function (str) {     // Accounts for decimal strings, ew
        return parseInt(str.toString()).toString(16);
    };
});
