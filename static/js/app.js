'use strict';

angular.module('angr', [
    'ngRoute',
    'angr.controllers',
    'angr.directives',
]).
config(['$routeProvider', function($routeProvider) {
    $routeProvider
        .when('/', {templateUrl: '/static/partials/index.html', controller: 'IndexCtrl'})
        .otherwise({redirectTo: '/'});
}]);
