'use strict';

var dirs = angular.module('angr.directives', ['angr.filters', 'angr.view', 'angr.contextMenu', 'angr.tools']);
dirs.directive('newproject', function() {
    return {
        templateUrl: '/static/partials/newproject.html',
        restrict: 'AE',
        scope: {
            projects: '='
        },
        controller: function($scope) {
            $scope.project = {};
            $scope.project.name = "";
            $scope.project.file = null;

            $scope.create = function () {
                if (!$scope.project.name || !$scope.project.file) return;
                AngrData.newProject($scope.project, function (data) {
                    alert('project created!');
                    $scope.projects.push({
                        name: data.name,
                        instances: []
                    });
                    $scope.project.file = null;
                    $scope.project.name = "";
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

dirs.directive('connectproject', function ($location, AngrData) {
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
                    AngrData.connectProject($scope.hostname, $scope.port, function (data) {
                        $scope.thinking = false;
                        $location.path('/instance/' + data.id);
                    }, function (data) {
                        $scope.thinking = false;
                        alert(data.message);
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

dirs.directive('bblock', function(ContextMenu, Schedule) {
    return {
        priority: 100,
        templateUrl: '/static/partials/bblock.html',
        restrict: 'AE',
        scope: {
            block: '=',
            view: '='
        },
        controller: function($scope, $element) {
            var updateBlock = function (block, ob) { 
                if (block === ob) return;
                $scope.irsb = null;
                $scope.simproc = null;
                $scope.error = false;
                $scope.text = '';
                if (block in $scope.view.gcomm.simProcedureSpots) {
                    $scope.simproc = $scope.view.gcomm.simProcedures[$scope.view.gcomm.simProcedureSpots[block]];
                    $scope.text = $scope.simproc.prettyName;
                } else if (block in $scope.view.gcomm.irsbs) {
                    $scope.irsb = $scope.view.gcomm.irsbs[block];
                    $scope.text = 'block_' + parseInt($scope.block.toString()).toString(16);
                } else {
                    $scope.error = 'WTF??';
                }
            };

            $scope.$watch('block', updateBlock);
            $scope.$watch('view.gcomm.simProcedureSpots', updateBlock);
            $scope.$watch('view.gcomm.irsbs');

            updateBlock($scope.block, null);


        },
        link: function ($scope, element, attrs) {
            $scope.view.comm.hack.delaybb.push(function () {
                var el = element[0];
                el.parentElement.style.width = Math.ceil(el.parentElement.getBoundingClientRect().width) + 'px';
            });
            ContextMenu.registerEntries(element, function () {
                return [
                    {
                        text: 'Basic block actions',
                        subitems: [
                            {
                                text: 'Expand all instructions',
                                action: function () {
                                    var boollist = $scope.view.comm.hack.expandedStmts[$scope.block];
                                    var keys = Object.keys(boollist);
                                    for (var i = 0; i < keys.length; i++) {
                                        boollist[keys[i]] = true;
                                    }
                                    $scope.view.comm.graph.layout();
                                }
                            }, {
                                text: 'Collapse all instructions',
                                action: function () {
                                    var boollist = $scope.view.comm.hack.expandedStmts[$scope.block];
                                    var keys = Object.keys(boollist);
                                    for (var i = 0; i < keys.length; i++) {
                                        boollist[keys[i]] = false;
                                    }
                                    $scope.view.comm.graph.layout();
                                }
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
                connector:[ "Flowchart", { stub:[40, 60], gap:10, cornerRadius:15} ],
                connectorStyle: {
                    lineWidth: 4,
                    strokeStyle: 'blue'
                }
            };

            var GRID_SIZE = 20;
            var HEADER = 160;

            $scope.layout = function() {
                Schedule(function () {
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
                });
            };

            $scope.view.comm.graph.layout = $scope.layout;

            // Tell JS to queue (timeout at zero seconds) this init routine
            // It needs to run later, after angular has finished processing shit
            // and has parsed the ng-ifs and ng-repeats
            Schedule(function() {
                if ($scope.view.comm.hack.delaybb.length > 0) {
                    for (var i = 0; i < $scope.view.comm.hack.delaybb.length; i++) {
                        $scope.view.comm.hack.delaybb[i]();
                    }
                    $scope.view.comm.hack.delaybb = [];
                }
                var graphRoot = jQuery($element).find('#graphRoot');
                $scope.plumb.setContainer(graphRoot);
                graphRoot.children('div').each(function(i, e) {
                    var $e = jQuery(e);
                    $scope.plumb.draggable($e, {grid: [GRID_SIZE, GRID_SIZE]});
                    $scope.plumb.addEndpoint(e.id, entryEndpoint, {anchor: 'TopCenter', uuid: e.id + '-entry'});
                    $scope.plumb.addEndpoint(e.id, exitEndpoint, {anchor: 'BottomCenter', uuid: e.id + '-exit'});
                });

                for (var i in $scope.edges) {
                    var edge = $scope.edges[i];
                    $scope.plumb.connect({
                        uuids: [edge.from + '-exit', edge.to + '-entry'],
                        detachable: false,
                    });
                }

                $scope.layout();
            });

            $scope.$watch('nodes', function (nv, ov) {
                $scope.layout();
            }, true);

            $scope.zoom = function (inout) {
                var czoom = parseInt($element[0].parentElement.style.zoom);
                if (czoom !== czoom) { // NaN, lol hax
                    czoom = 100;
                }
                if (inout) {
                    czoom *= 1.1;
                } else {
                    czoom /= 1.1;
                }

                if (czoom > 250) {
                    czoom = 250;
                } else if (czoom < 25) {
                    czoom = 25;
                }
                $element[0].parentElement.style.zoom = czoom.toString() + '%';
            };
        }
    };
});

dirs.directive('cfg', function(ContextMenu, AngrData) {
    return {
        templateUrl: '/static/partials/cfg.html',
        restrict: 'AE',
        scope: {
            view: '='
        },
        controller: function($scope, $http) {
            $scope.$watch('view.comm.funcPicker.selected', function (func) {
                if (!func) return;
                func.irsbsLoaded = false;
                AngrData.loadIRSBs(func, function () {
                    func.irsbsLoaded = true;
                });
            });
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

dirs.directive('funcpicker', function(AngrData) {
    return {
        templateUrl: '/static/partials/funcpicker.html',
        restrict: 'AE',
        scope: {
            view: '='
        },
        controller: function($scope) {
            $scope.click = function (func) {
                $scope.view.comm.funcPicker.selected = func;
            };
        }
    };
});

dirs.directive('funcman', function (AngrData) {
    return {
        templateUrl: '/static/partials/funcman.html',
        restrict: 'AE',
        scope: {
            view: '='
        },
        controller: function ($scope) {
            $scope.scopeBreak = {
                newName: ''
            };
            $scope.thinking = false;
            $scope.rename = function() {
                var f = $scope.view.comm.funcPicker.selected;
                if (f.name == $scope.scopeBreak.newName) return; // Don't submit a no-op request!
                f.name = $scope.scopeBreak.newName;
                $scope.thinking = true;
                AngrData.renameFunction(f, function () {
                    $scope.thinking = false;
                }, function (data) {
                    alert(data.message);
                    $scope.thinking = false;
                });
            };
            $scope.$watch('view.comm.funcPicker.selected', function(sf) {
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
            view: '='
        },
        controller: function ($scope, $element) {
            $scope.$watch('view.comm.funcPicker.selected', function (nv) {
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
                $scope.view.comm.funcPicker.selected = $scope.node;
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

dirs.directive('irsb', function(Schedule) {
    return {
        templateUrl: '/static/partials/irsb.html',
        restrict: 'E',
        scope: {
            irsb: '=data',
            view: '='
        },
        controller: function($scope) {
            $scope.renderData = {idx: -1, insn: 0, show: {}};
            $scope.view.comm.hack.expandedStmts[$scope.irsb.addr] = $scope.renderData.show;

            $scope.nextStmt = function (data) {
                data.idx++;
                return $scope.getCtx(data);
            };

            $scope.nextInsn = function (data) {
                data.insn++;
                data.show[data.insn] = false;
                return $scope.getCtx(data);
            };

            $scope.getCtx = function (data) {
                return {
                    stmtnum: data.idx,
                    insnnum: data.insn
                };
            };

            $scope.toggle = function (data, ld) {
                data.show[ld.insnnum] = !data.show[ld.insnnum];
                $scope.view.comm.graph.layout();
            };
        },
    };
});

dirs.directive('asmstmt', function () {
    return {
        templateUrl: '/static/partials/asmstmt.html',
        restrict: 'AE',
        scope: {
            view: '=',
            addr: '='
        },
        controller: function ($scope) {

        }
    }
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



dirs.directive('onEnter', function() {
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

dirs.directive('realClick', function() {
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
