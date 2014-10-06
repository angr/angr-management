'use strict';

var ctrls = angular.module('angr.controllers', ['dialogs.main']);

ctrls.controller('IndexCtrl', function($scope, $http, projects) {
    $scope.projects = projects;
});

ctrls.controller('ProjectCtrl', function($scope, $http, $routeParams, $interval, $modal, projects) {
    for (var i = 0; i < projects.length; i++) {
        if (projects[i].name === $routeParams['name']) {
            $scope.project = projects[i];
            break
        }
    }
    $scope.tabs = [];
    $scope.activeTab = null;
    $scope.addTab = function () {
        var dlg = $modal.open({
            templateUrl: '/static/partials/add_tab.html', 
            controller: 'AddTabCtrl', 
            scope: $scope, 
            size: 'lg'
        });
        dlg.result.then(function (data) {
            $scope.tabs.push(data);
            $scope.activeTab = $scope.tabs.length - 1;
        });
    };
    $scope.activateTab = function (tabIndex) {
        $scope.activeTab = tabIndex;
    };
    $scope.activating = false;
    $scope.activate = function() {
        $scope.activating = true;
        $http.post('/api/projects/' + $scope.project.name + '/activate')
            .success(function() {
                $scope.project.activated = true;
                $scope.activating = false;
            }).error(function() {
                $scope.activating = false;
            });
    };
    var handleCFG = function(data) {
        var prefix = "asdf";
        var blockToColor = {};
        var colors = randomColor({count: Object.keys(data.functions).length,
                                  luminosity: 'light'});
        var i = 0;
        for (var addr in data.functions) {
            var blocks = data.functions[addr];
            for (var j in blocks) {
                blockToColor[blocks[j]] = colors[i];
            }
            i += 1;
        }
        $scope.cfgNodes = {};
        for (var i in data.nodes) {
            var node = data.nodes[i];
            var id = node.type + (node.type === 'IRSB' ? node.addr : node.name);
            if (node.addr) {
                node.color = blockToColor[node.addr];
            }
            $scope.cfgNodes[id] = node;
        }
        $scope.cfgEdges = [];
        for (var i in data.edges) {
            var edge = data.edges[i];
            var fromId = edge.from.type + (edge.from.type === 'IRSB' ? edge.from.addr : edge.from.name);
            var toId = edge.to.type + (edge.to.type === 'IRSB' ? edge.to.addr : edge.to.name);
            $scope.cfgEdges.push({from: fromId, to: toId});
        }
        $scope.viewState = 'cfg';
    };
    $scope.genCFG = function() {
        $http.get('/api/projects/' + $scope.project.name + '/cfg')
            .success(function(data) {
                var periodic = $interval(function() {
                    $http.get('/api/tokens/' + data.token).success(function(res) {
                        if (res.ready) {
                            $interval.cancel(periodic);
                            handleCFG(res.value);
                        }
                    }).error(function() {
                        $interval.cancel(periodic);
                    });
                }, 1000);
            });
    };
    $scope.genDDG = function() {
        $http.get('/api/projects/' + $scope.project.name + '/ddg')
            .success(function(data) {
                console.log(data);
            });
    };
});

ctrls.controller('AddTabCtrl', function ($scope, $http, $modalInstance) {
    console.log($scope);
    console.log($modalInstance);
    $scope.data = {
        type: null
    };
    $scope.cancel = function () {
        $modalInstance.dismiss("Canceled");
    };
    $scope.thinking = false;
    $scope.add = function () {
        switch ($scope.data.type) {
            case 'CFG':
                $scope.data.title = 'CFG Tab';
                $modalInstance.close($scope.data);
                break;
            case 'SURVEYOR':
                $scope.data.title = 'Surveyor Tab';
                var kwargs = { };
                if ($scope.surveyorType == "Explorer") {
                    var flds = $scope.surveyorFields;  // brevity
                    kwargs['find'] = "PYTHON:"+flds['find'];
                    kwargs['avoid'] = "PYTHON:"+flds['avoid'];
                    kwargs['restrict'] = "PYTHON:"+flds['restrict'];
                    if (flds['min_depth'] != undefined) kwargs['min_depth'] =     parseInt(flds['min_depth']);
                    if (flds['max_depth'] != undefined) kwargs['max_depth'] =     parseInt(flds['max_depth']);
                    if (flds['max_repeats'] != undefined) kwargs['max_repeats'] = parseInt(flds['max_repeats']);
                    if (flds['num_find'] != undefined) kwargs['num_find'] =       parseInt(flds['num_find']);
                    if (flds['num_avoid'] != undefined) kwargs['num_avoid'] =     parseInt(flds['num_avoid']);
                    if (flds['num_deviate'] != undefined) kwargs['num_deviate'] = parseInt(flds['num_deviate']);
                    if (flds['num_loop'] != undefined) kwargs['num_loop'] =       parseInt(flds['num_loop']);
                }

                $scope.thinking = true;
                $http.post("/api/projects/" + $scope.project.name + "/surveyors/new/"+ $scope.surveyorType, {kwargs:kwargs}).success(function(data, status) {
                    $scope.thinking = false;
                    $scope.data.surveyorData = data;
                    $modalInstance.close($scope.data);
                });
                break;
            default:
                return;
        }
    };


    $scope.surveyorType = "Explorer";
    $scope.surveyorTypes = ['Explorer', 'Executor', 'Escaper', 'Slicecutor'];
    $scope.surveyorFields = { };

    $scope.surveyorFields['find'] = "( )";
    $scope.surveyorFields['avoid'] = "( )";
    $scope.surveyorFields['restrict'] = "( )";
    $scope.surveyorFields['min_depth'] = "1";
    $scope.surveyorFields['max_repeats'] = "10";
    $scope.surveyorFields['num_find'] = "1";
    $scope.surveyorFields['num_avoid'] = "1000000";
    $scope.surveyorFields['num_deviate'] = "1000000";
    $scope.surveyorFields['num_loop'] = "1000000";

    $scope.surveyorFieldDescriptions = {
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
    };
});
