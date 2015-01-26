'use strict';

var dirs = angular.module('angr.directives', ['angr.filters', 'angr.context', 'angr.tools', 'ui.bootstrap']);
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

/* yay!
dirs.directive('viewlayout', function (RecursionHelper) {
    return {
        templateUrl: '/static/partials/viewlayout.html',
        restrict: 'AE',
        scope: {
            view: '=',
            instance: '=',
            uictx: '='
        },  // no controller because #swag
        compile: RecursionHelper.compile
    };
});
*/

dirs.directive('bblock', function bblock(Context, Schedule, gcomm) {
    return {
        priority: 100,
        templateUrl: '/static/partials/bblock.html',
        restrict: 'AE',
	require: '^workspace',
        scope: {
            block: '=',
            uictx: '='
        },
        link: {pre: function ($scope, element, attrs, wk) {
	    $scope.comm = wk.comm;
	    var updateBlock = function (block, ob) {
                if (block === ob) {
                    return;
                }
                $scope.irsb = null;
                $scope.simproc = null;
                $scope.error = false;
                $scope.text = '';
                if (block in gcomm.simProcedureSpots) {
                    $scope.simproc = gcomm.simProcedures[gcomm.simProcedureSpots[block]];
                    $scope.text = $scope.simproc.prettyName;
                } else if (block in gcomm.irsbs) {
                    $scope.irsb = gcomm.irsbs[block];
                    $scope.text = 'block_' + parseInt($scope.block.toString()).toString(16);
                } else {
                    $scope.error = 'WTF??';
                }
            };

            wk.comm.$watch('surveyors.viewingSurveyor', function (s) {
                $scope.surveyorConnected = s !== null;
            });

            wk.comm.$watch('surveyors.currentBreakpoint', function (bp) {
                $scope.isBreakingHere = bp === parseInt($scope.block.toString());
            });

            $scope.breakHere = function () {
                var addr = parseInt($scope.block.toString());
                wk.comm.surveyors.currentBreakpoint = addr;
            };

            $scope.$watch('block', updateBlock);
            gcomm.$watch('simProcedureSpots', updateBlock);
            gcomm.$watch('irsbs');

            updateBlock($scope.block, null);

            var interactionActions = new Context.Actions({children: [{
                name: 'Option 1',
                action: function () {alert('EVERYTHING IS AWESOME');},
                keyboardShortcut: '+e'
            }, {
                name: 'Option 2',
                action: function () {alert('EVERYTHING IS COOL WHEN YOU\'RE PART OF A TEAM');},
                keyboardShortcut: 'S+E'
            }, {
                name: 'Option List',
                children: [{
                    name: 'Option 1a',
                    action: function () {alert('option 1a pressed');}
                },{
                    name: 'Option 1b',
                    action: function () {alert('option 1b pressed');}
                }]
            }]});
            var interactionController = function () {
                var pos = $(element).parent().position();
                return {
                    coordinates: new Context.Point(pos.left, pos.top),
                    actions: interactionActions,
                    doubleClick: function () {alert('DO A DOUBLE CLICK\n\nPRESS Z OR R TWICE');}
                };
            };
            $scope.myuictx = new Context.Interactable($scope.uictx, $(element), interactionController, 'BASIC_BLOCK');

            wk.comm.graph.delayedFuncs.push(function () {
                var el = element[0];
                el.parentElement.style.width = Math.ceil(el.parentElement.getBoundingClientRect().width) + 'px';
            });
            /*
            Context.registerEntries(element, function () {
                return [
                    {
                        text: 'Basic block actions',
                        subitems: [
                            {
                                text: 'Expand all instructions',
                                action: function () {
                                    var boollist = wk.comm.cfg.expandedStmts[$scope.block];
                                    var keys = Object.keys(boollist);
                                    var i;
                                    for (i = 0; i < keys.length; i += 1) {
                                        boollist[keys[i]] = true;
                                    }
                                    wk.comm.graph.layout();
                                }
                            }, {
                                text: 'Collapse all instructions',
                                action: function () {
                                    var boollist = wk.comm.cfg.expandedStmts[$scope.block];
                                    var keys = Object.keys(boollist);
                                    for (var i = 0; i < keys.length; i++) {
                                        boollist[keys[i]] = false;
                                    }
                                    wk.comm.graph.layout();
                                }
                            }, {
                                text: 'Reanalyze'
                            }
                        ]
                    }
                ];
            });
	    */
        }}
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

dirs.directive('graph', function(Context, gcomm, Schedule) {
    return {
        templateUrl: '/static/partials/graph.html',
        restrict: 'AE',
	require: '^workspace',
        scope: {
            nodes: '=',
            edges: '=',
            nodeType: '=',
            graphId: '@',
            uictx: '='
        },
        controller: function($scope, $element, LayoutCache) {
            jsPlumb.Defaults.MaxConnections = 10000;
            $scope.plumb = jsPlumb.getInstance({
                ConnectionOverlays: [
                    ["Arrow", {location: 1}]
                ]
            });

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

            $scope.$watch('nodes', function (nv, ov) {
                $scope.truNodes = $scope.nodes;
                if (!Array.prototype.isPrototypeOf($scope.truNodes)) {
                    $scope.truNodes = Object.keys($scope.truNodes);
                }
                Schedule(function () {
                    $scope.plumb.reset();
                    $scope.plumbing();
                });
            }, true);

            $scope.zoom = function (inout) {
                var czoom = parseInt($element[0].parentElement.style.zoom);
                if (isNaN(czoom)) {
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
	},
	link: function($scope, element, attrs, wk) {
	    $scope.comm = wk.comm;
	    $scope.gcomm = gcomm;
            wk.comm.graph.layout = $scope.layout;

            var GRID_SIZE = 20;
            var HEADER = 160;

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

            // Tell JS to queue (timeout at zero seconds) this init routine
            // It needs to run later, after angular has finished processing shit
            // and has parsed the ng-ifs and ng-repeats
            $scope.plumbing = function() {
                var i;
                for (i = 0; i < wk.comm.graph.delayedFuncs.length; i++) {
                    wk.comm.graph.delayedFuncs[i]();
                }
                wk.comm.graph.delayedFuncs = [];
                var graphRoot = jQuery(element).find('#graphRoot');
                $scope.plumb.setContainer(graphRoot);
                graphRoot.children('div').each(function(i, e) {
                    var $e = jQuery(e);
                    $scope.plumb.draggable($e, {grid: [GRID_SIZE, GRID_SIZE]});
                    $scope.plumb.addEndpoint(e.id, entryEndpoint, {anchor: 'TopCenter', uuid: e.id + '-entry'});
                    $scope.plumb.addEndpoint(e.id, exitEndpoint, {anchor: 'BottomCenter', uuid: e.id + '-exit'});
                });

		var pathTransitions = new Set();
		if (wk.comm.surveyors.viewingPath) {
		    var path = gcomm.paths[wk.comm.surveyors.viewingPath];
                    var backtrace = path.addr_backtrace;
		    for (var c = 0; c < backtrace.length - 1; c++) {
			pathTransitions.add(backtrace[c] + "->" + backtrace[c+1]);
		    }
		    pathTransitions.add(backtrace[backtrace.length-1] + "->" + path.last_addr);
		}

                for (i in $scope.edges) {
                    var edge = $scope.edges[i];
		    //console.log(edge.from + "->" + edge.to);
                    if ($scope.truNodes.indexOf(edge.to.toString()) != -1 && $scope.truNodes.indexOf(edge.from.toString()) != -1) {
			// note: setting paintStyle here doesn't seem to work...
                        var connection = $scope.plumb.connect({
                            uuids: [edge.from + '-exit', edge.to + '-entry'],
                            detachable: false
                        });

			if (pathTransitions.has(edge.from + "->" + edge.to)) {
			    connection.setPaintStyle({ strokeStyle: "#7CFC00" });
			}
                    }
                }

                Schedule($scope.layout);
            };

	    $scope.$watch('gcomm.paths[comm.surveyors.viewingPath].addr_backtrace', function(bt) {
		var pathTransitions = new Set();
		if (wk.comm.surveyors.viewingPath) {
		    var path = gcomm.paths[wk.comm.surveyors.viewingPath];
		    if (!path) { return; }
                    var backtrace = path.addr_backtrace;
		    if (!backtrace) { return; }
		    for (var c = 0; c < backtrace.length - 1; c++) {
			pathTransitions.add(backtrace[c] + "->" + backtrace[c+1]);
		    }
		    pathTransitions.add(backtrace[backtrace.length-1] + "->" + path.last_addr);
		}
		$scope.plumb.getConnections().forEach(function(c) {
		    if (pathTransitions.has(c.sourceId + "->" + c.targetId)) {
			c.setPaintStyle({ strokeStyle: "#7CFC00" });
		    }
		});
	    });

            wk.comm.$watch('graph.centerNode', function (nv) {
                if (!nv) return;
                var elm = jQuery(element).find('#graphRoot').find('#' + nv)[0];
                if (!elm) return;
                var cont = jQuery(element).parent()[0];
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

dirs.directive('cfg', function(Context, AngrData, defaultError) {
    return {
        templateUrl: '/static/partials/cfg.html',
        restrict: 'AE',
        scope: {
            data: '=',
            uictx: '='
        },
	require: '^workspace',
        link: {pre: function ($scope, element, attrs, wk) {
	    $scope.comm = wk.comm;
	    wk.comm.foo = "asdf";
	    wk.comm.$watch('funcPicker.selected', function (func) {
                if (!func) return;
                func.irsbsLoaded = false;
                AngrData.loadIRSBs(func).then(function () {
                    func.irsbsLoaded = true;
                }, defaultError);
            });
            wk.comm.$watch('cfg.jumpToBlock', function (nv) {
                if (!nv) return;
                wk.comm.graph.centerNode = nv.toString();
            });
        }}
    };
});

dirs.directive('addressName', function (gcomm) {
    return {
        templateUrl: '/static/partials/addressname.html',
	require: '^workspace',
        scope: {
            'address': '=addressName',
            'disableHighlight': '=',
            'allowFuncNames': '=',
            'disableClick': '='
        },
        restrict: 'A',
        link: {pre: function ($scope, element, attrs, wk) {
	    $scope.gcomm = gcomm;
            if (!$scope.disableHighlight) {
                element.on('mouseenter', function (e) {
                    $scope.$apply(function() {
                        element.addClass('highlight');
                        wk.comm.cfgHighlight2.blocks[$scope.address] = true;
                    });
                });
                element.on('mouseleave', function (e) {
                    $scope.$apply(function() {
                        element.removeClass('highlight');
                        wk.comm.cfgHighlight2.blocks[$scope.address] = false;
                    });
                });
            }
            if (!$scope.disableClick) {
                element.on('click', function (e) {
                    $scope.$apply(function() {
                        if ($scope.allowFuncNames && gcomm.funcMan.functions.hasOwnProperty($scope.address)) {
                            wk.comm.funcPicker.selected = gcomm.funcMan.functions[$scope.address];
                            wk.comm.cfgHighlight2.blocks[$scope.address] = false;
                        } else {
                            wk.comm.cfg.jumpToBlock = $scope.address;
                        }
                    });
                });
            }
        }}
    };
});

dirs.directive('funcpicker', function($filter, gcomm) {
    return {
        templateUrl: '/static/partials/funcpicker.html',
        restrict: 'AE',
	require: '^workspace',
        scope: {
	    data: '=',
        },
        link: {pre: function($scope, element, attrs, wk) {
	    $scope.comm = wk.comm;
	    $scope.gcomm = gcomm;
            $scope.filterby = '';
            $scope.getFuncList = function () {      // UGHHHHHH.
                var out = [];
                for (var key in gcomm.funcMan.functions) {
                    out.push(gcomm.funcMan.functions[key]);
                }
                return out;
            };
            $scope.filterfunc = function (value) {
                var name = $filter('funcnameextra')(value);
                if (name.indexOf($scope.filterby) != -1) {
                    return true;
                }
                return false;
            };

            $scope.click = function (func) {
                wk.comm.funcPicker.selected = func;
            };
        }}
    };
});

dirs.directive('funcman', function (AngrData) {
    return {
        templateUrl: '/static/partials/funcman.html',
        restrict: 'AE',
	require: '^workspace',
        scope: {
            data: '='
        },
        link: {pre: function ($scope, element, attrs, wk) {
	    $scope.comm = wk.comm;
            $scope.scopeBreak = {
                newName: ''
            };
            $scope.thinking = false;
            $scope.rename = function() {
                var f = wk.comm.funcPicker.selected;
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
            wk.comm.$watch('funcPicker.selected', function(sf) {
                if (!sf) return;
                $scope.scopeBreak.newName = sf.name;
            });

        }}
    };
});

dirs.directive('proxgraph', function (gcomm) {
    return {
        templateUrl: '/static/partials/proxgraph.html',
        restrict: 'AE',
	require: '^workspace',
        scope: {
            data: '='
        },
        link: {pre: function ($scope, element, attrs, wk) {
	    $scope.gcomm = gcomm;
            wk.comm.$watch('funcPicker.selected', function (nv) {
                if (!nv) return;
                wk.comm.graph.centerNode = nv.address.toString();
            });
        }}
    };
});

dirs.directive('funcnode', function funcnode() {
    return {
        templateUrl: '/static/partials/funcnode.html',
        restrict: 'AE',
        scope: {
            node: '='
        },
	require: '^workspace',
        link: {pre: function ($scope, element, attrs, wk) {
	    $scope.comm = wk.comm;
            $scope.click = function () {
                wk.comm.funcPicker.selected = $scope.node;
            };
        }}
    };
});

dirs.directive('irsb', function irsb(Schedule) {
    return {
        templateUrl: '/static/partials/irsb.html',
        restrict: 'E',
        scope: {
            irsb: '=data',
            data: '=',
            uictx: '='
        },
	require: '^workspace',
        link: {pre: function($scope, element, attrs, wk) {
            $scope.renderData = {idx: -1, insn: 0, show: {}};
            wk.comm.cfg.expandedStmts[$scope.irsb.addr] = $scope.renderData.show;

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
                Schedule(wk.comm.graph.layout);
            };
        }},
    };
});

dirs.directive('asmstmt', function (Context, gcomm) {
    return {
        templateUrl: '/static/partials/asmstmt.html',
        restrict: 'AE',
        scope: {
            addr: '=',
            uictx: '=',
            toggle: '&'
        },
        controller: function ($scope, $element) {
	    $scope.gcomm = gcomm;
            var interactionActions = new Context.Actions({children: [{
                name: 'Proof that we are in the asmstmt context',
                isEnabled: false
            }]});
            var interactionController = function () {
                var pos = $($element).parent().parent().position();
                return {
                    coordinates: new Context.Point(pos.left, pos.top),
                    actions: interactionActions,
                    doubleClick: function () {$scope.toggle();}
                };
            };
            $scope.myuictx = new Context.Interactable($scope.uictx, $($element).parent(), interactionController, 'ASM_STMT');
        }
    };
});

dirs.directive('irstmt', function() {
    return {
        templateUrl: '/static/partials/irstmt.html',
        restrict: 'E',
        scope: {
            stmt: '=',
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
        },
        compile: RecursionHelper.compile,
        controller: function($scope, $http) {
            $scope.ops = {
                __add__: "+", __sub__: "-", __div__: "/", __truediv__: "/", __mul__: "*", __mod__: "%",
                __eq__: "==", __ne__: "!=", __ge__: ">=", __gt__: ">", __le__: "<=", __lt__: "<",
                __neg__: "-", __or__: "|", __and__: "&", __xor__: "^", __invert__: "~",
                __lshift__: "<<", __rshift__: ">>"
            };
        }
    };
});

dirs.directive('irtmp', function irtmp(Context) {
    return {
        templateUrl: '/static/partials/irtmp.html',
        restrict: 'E',
        scope: {
            tmp: '=',
        },
	require: '^workspace',
        link: function ($scope, element, attrs, wk) {
	    $scope.comm = wk.comm;
            $scope.mouse = function (over) {
                wk.comm.cfgHighlight.tmps[$scope.tmp] = over;
            };
        }
    };
});

dirs.directive('irreg', function($tooltip, AngrData, gcomm) {
    return {
        templateUrl: '/static/partials/irreg.html',
        restrict: 'E',
        scope: {
            offset: '=',
            size: '=',
            operation: '=',
            stmtid: '=',
        },
	require: '^workspace',
        link: function (scope, elem, attrs, wk) {
	    scope.comm = wk.comm;
	    scope.gcomm = gcomm;
            scope.hover = false;
            scope.exprVal = {expr_type: ''};
            scope.showVal = false;

            scope.toggleVal = function () {
                scope.showVal = !scope.showVal;

                if (scope.showVal) {
                    AngrData.findExprVal(wk.comm.surveyors.viewingSurveyor,
                                         wk.comm.surveyors.viewingPath,
                                         {expr_type: 'reg', reg: scope.offset,
                                         before: scope.stmtid})
                        .then(function(exprVal) {
                            scope.exprVal = exprVal.data;
                        });
                }
            };

            scope.mouse = function (over) {
                wk.comm.cfgHighlight.registers[scope.offset] = over;
            };
        }
    };
});

/*
dirs.directive('splittest', function (View) {
    return {
        templateUrl: '/static/partials/splittest.html',
        restrict: 'AE',
        scope: {
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
*/
