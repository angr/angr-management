'use strict';

angular.module('angr', [
    'ngRoute',
    'angr.controllers',
    'angr.directives',
    'angr.services',
]).
config(function($routeProvider, $locationProvider) {
    $routeProvider
        .when('/', {templateUrl: '/static/partials/index.html', controller: 'IndexCtrl',
                    resolve: {projects: function(Projects) { return Projects.projects(); }}})
        .when('/project/:name', {templateUrl: '/static/partials/project.html', controller: 'ProjectCtrl',
                                 resolve: {projects: function(Projects) { return Projects.projects(); }}})
        .otherwise({redirectTo: '/'});
});
