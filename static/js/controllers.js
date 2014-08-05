'use strict';

var ctrls = angular.module('angr.controllers', []);

ctrls.controller('IndexCtrl', function($scope, $http, projects) {
    $scope.projects = projects;
});

ctrls.controller('ProjectCtrl', function($scope, $http, $routeParams, projects) {
    $scope.project = projects[$routeParams['name']];
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
    $scope.getCFG = function() {
        if ($scope.project.activated) {
            $http.get('/api/projects/' + $scope.project.name + '/cfg')
                .success(function(data) {
                    console.log(data);
                });
        }
    };
});
