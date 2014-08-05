'use strict';

var srvcs = angular.module('angr.services', []);
srvcs.factory('Projects', function($http) {
    var projects = $http.get('/api/projects/').then(function(res) { return res.data; });

    return {
        projects: function() { return projects; }
    };
});
