'use strict';

angular.module('angr', [
    'ngRoute',
    'angr.controllers',
    'angr.directives',
    'angr.services',
    'angr.tiles',
    'angr.workspaces',
    'ui.bootstrap'
]).
config(function($routeProvider, $locationProvider) {
    $routeProvider
        .when('/', {templateUrl: '/static/partials/index.html', controller: 'IndexCtrl',
                    resolve: {projects: function(Projects) { return Projects.projects(); }}})
        .when('/instance/:inst_id', {templateUrl: '/static/partials/project.html', controller: 'ProjectCtrl',
                                 resolve: {projects: function(Projects) { return Projects.projects(); }}})
        .when('/project/:inst_id/surveyor/:surveyor_id', {
        	templateUrl: '/static/partials/surveyor_page.html', controller: 'SurveyorCtrl',
                                 resolve: {projects: function(Projects) { return Projects.projects(); }}})
        .otherwise({redirectTo: '/'});
});
