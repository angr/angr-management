'use strict';

var dirs = angular.module('angr.directives', ['angr.filters', 'angr.view', 'angr.contextMenu', 'angr.tools', 'ui.bootstrap']);
dirs.directive('newproject', function(AngrData, defaultError) {
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
                if (!$scope.project.name || !$scope.project.file) {
                    return;
                }
                AngrData.newProject($scope.project).then(function (data) {
                    alert('project created!');
                    $scope.projects.push({
                        name: data.name,
                        instances: []
                    });
                    $scope.project.file = null;
                    $scope.project.name = "";
                }, defaultError);
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
    };
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
                    AngrData.connectProject($scope.hostname, $scope.port).then(function (data) {
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
                if (e.target != element[0]) {
                    return blankHandler(e);
                }
                if (e.clientX > rect.left && e.clientX < rect.right && e.clientY > rect.top && e.clientY < rect.bottom) {
                    return blankHandler(e);
                }
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
                if (block === ob) {
                    return;
                }
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
            $scope.view.comm.graph.delayedFuncs.push(function () {
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
                                    var boollist = $scope.view.comm.cfg.expandedStmts[$scope.block];
                                    var keys = Object.keys(boollist);
                                    var i;
                                    for (i = 0; i < keys.length; i += 1) {
                                        boollist[keys[i]] = true;
                                    }
                                    $scope.view.comm.graph.layout();
                                }
                            }, {
                                text: 'Collapse all instructions',
                                action: function () {
                                    var boollist = $scope.view.comm.cfg.expandedStmts[$scope.block];
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

var betterLayout = function(graph) {
    graph.nodes().forEach(function(id) {
        var node = graph.node(id);
        node.width /= 72.0;
        node.height /= 72.0;
    });
    graph.graph().edgesep /= 72.0;
    graph.graph().nodesep /= 72.0;
    graph.graph().ranksep /= 72.0;
    var dotRepr = graphlibDot.write(graph);
    var laidOut = Viz(dotRepr, 'dot');
    var laidOutGraph = graphlibDot.read(laidOut);
    var width = parseInt(laidOutGraph.graph().bb.split(',')[2], 10);
    var height = parseInt(laidOutGraph.graph().bb.split(',')[3], 10);
    laidOutGraph.nodes().forEach(function(id) {
        var node = laidOutGraph.node(id);
        node.x = parseInt(node.pos.split(',')[0], 10);
        node.y = height - parseInt(node.pos.split(',')[1], 10);
    });
    return laidOutGraph;
};

dirs.directive('graph', function(ContextMenu) {
    return {
        templateUrl: '/static/partials/graph.html',
        restrict: 'AE',
        scope: {
            nodes: '=',
            edges: '=',
            view: '=',
            nodeType: '=',
            graphId: '@',
        },
        controller: function($scope, $element, Schedule, LayoutCache) {
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
                var actuallyLayout = function(g) {
                    var entryId;
                    g.nodes().forEach(function(id) {
                        var data = g.node(id);
                        var $e = jQuery('#' + id);
                        var roundedCenterX = HEADER + GRID_SIZE * Math.round(data.x/GRID_SIZE);
                        var roundedCenterY = HEADER + GRID_SIZE * Math.round(data.y/GRID_SIZE);
                        $e.css('left', roundedCenterX - data.width/2);
                        $e.css('top', roundedCenterY - data.height/2);

                        if (g.predecessors(id).length == 0) {
                            entryId = id;
                        }
                    });
                    document.getElementById(entryId).scrollIntoView();
                    $scope.plumb.repaintEverything();
                };

                if (LayoutCache.cache.hasOwnProperty($scope.graphId)) {
                    actuallyLayout(LayoutCache.cache[$scope.graphId]);
                    return;
                }

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
                        if ($scope.truNodes.indexOf(edge.from.toString()) != -1 && $scope.truNodes.indexOf(edge.to.toString()) != -1) {
                            g.setEdge(edge.from.toString(), edge.to.toString());
                        }
                    }
                    //dagre.layout(g);
                    var laidOut = betterLayout(g);
                    actuallyLayout(laidOut);
                    LayoutCache.cache[$scope.graphId] = laidOut;
                });
            };

            $scope.view.comm.graph.layout = $scope.layout;

            // Tell JS to queue (timeout at zero seconds) this init routine
            // It needs to run later, after angular has finished processing shit
            // and has parsed the ng-ifs and ng-repeats
            var plumbing = function() {
                var i;
                for (i = 0; i < $scope.view.comm.graph.delayedFuncs.length; i++) {
                    $scope.view.comm.graph.delayedFuncs[i]();
                }
                $scope.view.comm.graph.delayedFuncs = [];
                var graphRoot = jQuery($element).find('#graphRoot');
                $scope.plumb.setContainer(graphRoot);
                graphRoot.children('div').each(function(i, e) {
                    var $e = jQuery(e);
                    $scope.plumb.draggable($e, {grid: [GRID_SIZE, GRID_SIZE]});
                    $scope.plumb.addEndpoint(e.id, entryEndpoint, {anchor: 'TopCenter', uuid: e.id + '-entry'});
                    $scope.plumb.addEndpoint(e.id, exitEndpoint, {anchor: 'BottomCenter', uuid: e.id + '-exit'});
                });

                for (i in $scope.edges) {
                    var edge = $scope.edges[i];
                    if ($scope.truNodes.indexOf(edge.to.toString()) != -1 && $scope.truNodes.indexOf(edge.from.toString()) != -1) {
                        $scope.plumb.connect({
                            uuids: [edge.from + '-exit', edge.to + '-entry'],
                            detachable: false,
                        });
                    }
                }

                $scope.layout();
            };

            $scope.$watch('nodes', function (nv, ov) {
                $scope.truNodes = $scope.nodes;
                if (!Array.prototype.isPrototypeOf($scope.truNodes)) {
                    $scope.truNodes = Object.keys($scope.truNodes);
                }
                Schedule(function () {
                    $scope.plumb.reset();
                    plumbing();
                });
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

            $scope.$watch('view.comm.graph.centerNode', function (nv) {
                if (!nv) return;
                var elm = jQuery($element).find('#graphRoot').find('#' + nv)[0];
                if (!elm) return;
                var cont = jQuery($element).parent()[0];
                if (!cont) return;

                var left = parseInt(elm.style.left);
                var width = elm.clientWidth;
                var clientWidth = cont.clientWidth;
                cont.scrollLeft = left + (width/2) - (clientWidth/2);

                var top = parseInt(elm.style.top);
                var height = elm.clientHeight;
                var clientHeight = cont.clientHeight;
                cont.scrollTop = top + (height/2) - (clientHeight/2);
            });
        }
    };
});

dirs.directive('cfg', function(ContextMenu, AngrData, defaultError) {
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
                AngrData.loadIRSBs(func).then(function () {
                    func.irsbsLoaded = true;
                }, defaultError);
            });
            $scope.$watch('view.comm.cfg.jumpToBlock', function (nv) {
                if (!nv) return;
                $scope.view.comm.graph.centerNode = nv.toString();
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
                ];
            });
        }
    };
});

dirs.directive('addressName', function () {
    return {
        templateUrl: '/static/partials/addressname.html',
        scope: {
            'address': '=addressName',
            'disableHighlight': '=',
            'allowFuncNames': '=',
            'disableClick': '=',
            'view': '='
        },
        restrict: 'A',
        link: function ($scope, element, attrs) {
            if (!$scope.disableHighlight) {
                element.on('mouseenter', function (e) {
                    $scope.$apply(function() {
                        element.addClass('highlight');
                        $scope.view.comm.cfgHighlight2.blocks[$scope.address] = true;
                    });
                });
                element.on('mouseleave', function (e) {
                    $scope.$apply(function() {
                        element.removeClass('highlight');
                        $scope.view.comm.cfgHighlight2.blocks[$scope.address] = false;
                    });
                });
            }
            if (!$scope.disableClick) {
                element.on('click', function (e) {
                    $scope.$apply(function() {
                        if ($scope.allowFuncNames && $scope.view.gcomm.funcMan.functions.hasOwnProperty($scope.address)) {
                            $scope.view.comm.funcPicker.selected = $scope.view.gcomm.funcMan.functions[$scope.address];
                            $scope.view.comm.cfgHighlight2.blocks[$scope.address] = false;
                        } else {
                            $scope.view.comm.cfg.jumpToBlock = $scope.address;
                        }
                    });
                });
            }
        }
    };
});

dirs.directive('funcpicker', function() {
    return {
        templateUrl: '/static/partials/funcpicker.html',
        restrict: 'AE',
        scope: {
            view: '='
        },
        controller: function($scope, $filter) {
            $scope.filterby = '';
            $scope.getFuncList = function () {      // UGHHHHHH.
                var out = [];
                for (var key in $scope.view.gcomm.funcMan.functions) {
                    out.push($scope.view.gcomm.funcMan.functions[key]);
                }
                return out;
            };
            $scope.filterfunc = function (value) {
                var name = $filter('funcnameextra')(value);
                if (name.indexOf($scope.filterby) != -1) {
                    return true;
                }
                return false;
            }

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
                AngrData.renameFunction(f).then(function () {
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
                if (!nv) return;
                $scope.view.comm.graph.centerNode = nv.address.toString();
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
            $scope.view.comm.cfg.expandedStmts[$scope.irsb.addr] = $scope.renderData.show;

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
            view: '=',
            stmtid: '=',
        },
    };
});

dirs.directive('irexpr', function(RecursionHelper) {
    return {
        templateUrl: '/static/partials/irexpr.html',
        restrict: 'E',
        scope: {
            expr: '=',
            view: '=',
            stmtid: '=',
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

dirs.directive('irreg', function($tooltip, AngrData) {
    return {
        templateUrl: '/static/partials/irreg.html',
        restrict: 'E',
        scope: {
            offset: '=',
            size: '=',
            operation: '=',
            view: '=',
            stmtid: '=',
        },
        link: function (scope, elem) {
            scope.hover = false;
            scope.exprVal = {expr_type: ''};
            scope.showVal = false;

            scope.toggleVal = function () {
                scope.showVal = !scope.showVal;

                if (scope.showVal) {
                    AngrData.findExprVal(scope.view.comm.surveyors.viewingSurveyor,
                                         scope.view.comm.surveyors.viewingPath,
                                         {expr_type: 'reg', reg: scope.offset,
                                         before: scope.stmtid})
                        .then(function(exprVal) {
                            console.log(exprVal);
                            scope.exprVal = exprVal.data;
                        });
                }
            };

            scope.mouse = function (over) {
                scope.view.comm.cfgHighlight.registers[scope.offset] = over;
            };
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

            $scope.close = function () {
                $scope.view.close();
            };
        }
    }
});
