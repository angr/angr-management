'use strict';

var ctrls = angular.module('angr.controllers', []);

ctrls.controller('IndexCtrl', function($scope, $http, projects) {
    $scope.projects = projects;
});

ctrls.controller('ProjectCtrl', function($scope, $http, $routeParams, projects) {
    $scope.project = projects[$routeParams['name']];
    $scope.activating = false;
    $scope.cfgNodes = null;
    $scope.cfgEdges = null;
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
    $scope.genCFG = function() {
        $http.get('/api/projects/' + $scope.project.name + '/cfg')
            .success(function(data) {
                var prefix = "asdf";
                $scope.cfgNodes = {};
                for (var i in data.nodes) {
                    var node = data.nodes[i];
                    var id = node.type + (node.type === 'IRSB' ? node.addr : node.name);
                    $scope.cfgNodes[id] = node;
                }
                console.log($scope.cfgNodes);
                $scope.cfgEdges = [];
                for (var i in data.edges) {
                    var edge = data.edges[i];
                    var fromId = edge.from.type + (edge.from.type === 'IRSB' ? edge.from.addr : edge.from.name);
                    var toId = edge.to.type + (edge.to.type === 'IRSB' ? edge.to.addr : edge.to.name);
                    $scope.cfgEdges.push({from: fromId, to: toId});
                }
            });
    };
    $scope.genDDG = function() {
        $http.get('/api/projects/' + $scope.project.name + '/ddg')
            .success(function(data) {
                console.log(data);
            });
    };
});
