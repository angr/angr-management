'use strict';

var dirs = angular.module('angr.directives', ['angr.filters']);
dirs.directive('newproject', function() {
    return {
        templateUrl: '/static/partials/newproject.html',
        restrict: 'AE',
        controller: function($scope, $http) {
            $scope.project = {};
            $scope.project.name = "my_cool_binary";
            $scope.project.file = null;
            $scope.create = function() {
                var config = {
                    url: '/api/projects/',
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
                $http(config).success(function() {
                    alert('project created!');
                }).error(function() {
                    alert('could not create project :(');
                });
            };
        }
    };
});

dirs.directive('loadfile', function($http) {
    return {
        templateUrl: '/static/partials/loadfile.html',
        restrict: 'AE',
        scope: {
            file: '=',
        },
        link: function($scope, element, attrs) {
            $scope.chosenURL = null;
            $scope.uploadURL = function() {
                var url;
                if ($scope.chosenURL.indexOf("http://") === 0) {
                    url = $scope.chosenURL.slice(7);
                } else if ($scope.chosenURL.indexOf("https://") === 0) {
                    url = $scope.chosenURL.slice(8);
                } else {
                    return;
                }
                console.log("http://www.corsproxy.com/" + url);
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

            element.bind('dragover', blankHandler);
            element.bind('dragenter', blankHandler);

            element.bind('drop', function(event) {
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

dirs.directive('bblock', function() {
    return {
        priority: 100,
        templateUrl: '/static/partials/bblock.html',
        restrict: 'AE',
        scope: {
            block: '=',
            showDetails: '=',
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
        }
    };
});

dirs.directive('graph', function() {
    return {
        templateUrl: '/static/partials/graph.html',
        restrict: 'AE',
        scope: {
            nodes: '=',
            edges: '=',
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
                maxConnections: -1,
                isTarget: true
            };
            var exitEndpoint = {
                maxConnections: -1,
                connector:[ "Flowchart", { stub:[40, 60], gap:10, cornerRadius:5, alwaysRespectStubs:true } ],
            };

            var GRID_SIZE = 20;
            var HEADER = 160;

            $scope.layout = function() {
                console.log('laying out');
                var g = new dagre.Digraph();
                jQuery($element).children('div').each(function(i, e) {
                    var $e = jQuery(e);
                    var id = $e.attr('id');
                    g.addNode(id, {width: $e.width(), height: $e.height()});
                });
                for (var i in $scope.edges) {
                    var edge = $scope.edges[i];
                    g.addEdge(null, edge.from, edge.to);
                }
                var layout = dagre.layout().nodeSep(400).edgeSep(400).rankSep(100).run(g);
                layout.eachNode(function(id, data) {
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
                    var $e = jQuery(e);
                    var id = $e.attr('id');
                    $scope.plumb.draggable($e, {grid: [GRID_SIZE, GRID_SIZE]});
                    $scope.plumb.addEndpoint(id, entryEndpoint, {anchor: 'TopCenter', uuid: id + '-entry'});
                    $scope.plumb.addEndpoint(id, exitEndpoint, {anchor: ['Continuous', {faces: ['bottom']}], uuid: id + '-exit'});
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
        },
    };
});

dirs.directive('surveyors', function($http) {
    return {
        templateUrl: '/static/partials/surveyors.html',
        restrict: 'AE',
        scope: { project: '=' },
        controller: function($scope, $http)
        {
            $scope.surveyor_type = "Explorer";
            $scope.surveyor_options = { };

            $scope.surveyor_options['find'] = "( )";
            $scope.surveyor_options['avoid'] = "( )";
            $scope.surveyor_options['restrict'] = "( )";
            $scope.surveyor_options['min_depth'] = "1";
            $scope.surveyor_options['max_repeats'] = "10";
            $scope.surveyor_options['num_find'] = "1";
            $scope.surveyor_options['num_avoid'] = "1000000";
            $scope.surveyor_options['num_deviate'] = "1000000";
            $scope.surveyor_options['num_loop'] = "1000000";

            $scope.options = {
                Explorer: {
                    find: 'Addresses to find (Python expression)',
                    avoid: 'Addresses to avoid (Python expression)',
                    restrict: 'Addresses to restrict the analysis to (Python expression)',
                    min_depth: 'The minimum number of blocks in a path before it can be culled',
                    max_repeats: 'The maximum repeats for a single block before a path is marked as "looping"',
                    num_find: 'Maximum number of paths to find before suspending the analysis',
                    num_avoid: 'Maximum number of paths to avoid before suspending the analysis',
                    num_deviate: 'Maximum number of paths to stop from deviating before suspending the analysis',
                    num_loop: 'Maximum number of paths to stop from looping before suspending the analysis',
                }
            }

            $scope.new_surveyor = function(type, options) {
                var kwargs = { };
                if (type == "Explorer")
            {
                kwargs['find'] = "PYTHON:"+options['find'];
                kwargs['avoid'] = "PYTHON:"+options['avoid'];
                kwargs['restrict'] = "PYTHON:"+options['restrict'];
                if (options['min_depth'] != undefined) kwargs['min_depth'] = parseInt(options['min_depth']);
                if (options['max_depth'] != undefined) kwargs['max_depth'] = parseInt(options['max_depth']);
                if (options['max_repeats'] != undefined) kwargs['max_repeats'] = parseInt(options['max_repeats']);
                if (options['num_find'] != undefined) kwargs['num_find'] = parseInt(options['num_find']);
                if (options['num_avoid'] != undefined) kwargs['num_avoid'] = parseInt(options['num_avoid']);
                if (options['num_deviate'] != undefined) kwargs['num_deviate'] = parseInt(options['num_deviate']);
                if (options['num_loop'] != undefined) kwargs['num_loop'] = parseInt(options['num_loop']);
            }

                $http.post("/api/projects/" + $scope.project.name + "/surveyors/new/"+type, {kwargs:kwargs}).success(function(data, status) {
                $scope.surveyors.push(data);
            });
            }

                $scope.surveyors = [ ];
                $http.get("/api/projects/" + $scope.project.name + "/surveyors").success(function(data, status) { $scope.surveyors = data; });

                $scope.surveyor_types = [ ];
                $http.get("/api/surveyor_types").success(function(data, status) { $scope.surveyor_types = data; });
        }
    }
});

dirs.directive('surveyor', function($http) {
    return {
        templateUrl: '/static/partials/surveyor.html',
        restrict: 'AE',
        scope: { sid: '=', project: "=", surveyor: '=data' },
        controller: function($scope, $http)
        {
            $scope.show_surveyor = false;
            if ($scope.surveyor == undefined)
            {
                $http.get("/api/projects/" + $scope.project.name + "/surveyors/" + $scope.sid).success(function(data, status) {
                    $scope.surveyor = data;
                });
            }

            $scope.steps = 1;
            $scope.step = function(steps) {
                $http.post("/api/projects/" + $scope.project.name + "/surveyors/" + $scope.sid + "/step", {steps: steps}).success(function(data, status) {
                    $scope.surveyor = data;
                });
            }

            $scope.reactivate = function(path) {
                $http.post("/api/projects/" + $scope.project.name + "/surveyors/" + $scope.sid + "/resume/" + path.id).success(function(data, status) {
                    $scope.surveyor = data;
                });
            }

            $scope.suspend = function(path) {
                $http.post("/api/projects/" + $scope.project.name + "/surveyors/" + $scope.sid + "/suspend/" + path.id).success(function(data, status) {
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
        },
    };
});

dirs.directive('irexpr', function(RecursionHelper) {
    return {
        templateUrl: '/static/partials/irexpr.html',
        restrict: 'E',
        scope: {
            expr: '=',
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
            }
        }
    };
});
