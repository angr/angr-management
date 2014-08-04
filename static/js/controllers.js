'use strict';

var ctrls = angular.module('angr.controllers', []);

ctrls.controller('IndexCtrl', function($scope, $http) {
    $http.get('/api/projects').success(function(projects) {
        $scope.projects = projects;
    });
});
