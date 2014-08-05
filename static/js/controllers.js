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
    $scope.getCFG = function() {
        if ($scope.project.activated) {
            $http.get('/api/projects/' + $scope.project.name + '/cfg')
                .success(function(data) {
                    var prefix = "asdf";
                    $scope.cfgNodes = {};
                    $scope.cfgEdges = [];
                    for (var i in data) {
                        var edge = data[i];
                        var fromId = edge.from.type + (edge.from.type === 'IRSB' ? edge.from.addr : edge.from.name);
                        var toId = edge.to.type + (edge.to.type === 'IRSB' ? edge.to.addr : edge.to.name);
                        [edge.from, edge.to].forEach(function(edge) {
                            if (edge.type === 'IRSB') {
                                edge.text = '0x' +  edge.addr.toString(16);
                            } else if (edge.type === 'proc') {
                                edge.text = edge.name;
                            }
                        });
                        $scope.cfgNodes[fromId] = edge.from;
                        $scope.cfgNodes[toId] = edge.to;
                        $scope.cfgEdges.push({from: fromId, to: toId});
                    }
                });
        }
    };
});
