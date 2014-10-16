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
                        console.log($scope.file);
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
                //console.log("http://www.corsproxy.com/" + url);
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
                console.log(file);

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
        },
        controller: function($scope, $element, $timeout) {
            jsPlumb.Defaults.MaxConnections = 10000;
            $scope.plumb = jsPlumb.getInstance({
                ConnectionOverlays: [
                    ["Arrow", {location: 1}]
                ]
            });
            $scope.plumb.setContainer($element);

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
                console.log('laying out');
                var g = new graphlib.Graph()
                    .setGraph({ nodesep: 200, edgesep: 200, ranksep: 100 })
                    .setDefaultEdgeLabel(function() { return {}; });
                jQuery($element).children('div').each(function(i, e) {
                    var $e = jQuery(e);
                    var id = $e.attr('id');
                    g.setNode(id, {width: $e.width(), height: $e.height()});
                });
                for (var i in $scope.edges) {
                    var edge = $scope.edges[i];
                    g.setEdge(edge.from, edge.to);
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

            // VERY HACKY (but it works)
            $timeout(function() {
                jQuery($element).children('div').each(function(i, e) {
                    //console.log(e);
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

                $scope.layout();
            }, 0);
        }
    };
});

dirs.directive('cfg', function(ContextMenu) {
    return {
        templateUrl: '/static/partials/cfg.html',
        restrict: 'AE',
        scope: {
            instance: '=',
            view: '='
        },
        controller: function($scope, $http, $interval) {
            //console.log(angular.extend({}, $scope));
            var handleCFG = function(data) {
                $scope.view.data.rawCFGData = data;
                //console.log(angular.extend({}, $scope));
                $scope.view.data.loaded = true;
                //console.log("handling cfg");

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
                        var fireTokenQuery = function() {
                            $http.get('/api/tokens/' + data.token).success(function(res) {
                                if (res.ready) {
                                    handleCFG(res.value);
                                } else {
                                    fireTokenQuery();
                                }
                            }).error(function() {
                                // TODO: Bad
                            });
                        };
                        fireTokenQuery();
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

dirs.directive('functions', function() {
    return {
        templateUrl: '/static/partials/functions.html',
        restrict: 'AE',
        scope: {
            instance: '=',
            view: '=',
            comm: '=',
        },
        controller: function($scope, $http) {
            if (!$scope.view.data.loaded) {
                $scope.view.data.loaded = false;
                $http.get('/api/instances/' + $scope.instance + '/functions')
                    .success(function(data) {
                        $scope.view.data.selectedFunc = null;
                        $scope.view.data.loaded = true;
                        $scope.view.data.functions = data;
                    });
            }
            $scope.rename = function(f) {
                $http.post('/api/instances/' + $scope.instance + '/functions/' + f.addr + '/rename', f.name)
                    .success(function() {
                        $scope.f.nameTainted = false;
                    });
            };
            $scope.$watch('view.data.selectedFunc', function(sf) {
                if (!sf || !$scope.view.data.functions) { return; }
                $scope.view.comm.selectedFunc = sf;
                $scope.f = $scope.view.data.functions.filter(function(f) {
                    return f.addr == sf;
                })[0];
            });
        }
    }
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
            //console.log($scope.view);
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
