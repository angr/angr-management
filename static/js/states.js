var states = angular.module('angr.states', ['angr.tools']);

states.directive('state', function($http) {
    return {
        templateUrl: '/static/partials/state.html',
        restrict: 'E',
        scope: { sid: '=sid', pid: '=pid' },
        controller: function($scope, $http, AngrData) {
            $scope.state = null;
            AngrData.pathGetState($scope.sid, $scope.pid).then(function(data) {
                $scope.state = data;
            });
        }
    };
});

states.directive('stateRegisters', function($http) {
    return {
        templateUrl: '/static/partials/state_registers.html',
        restrict: 'AE',
        scope: { state: '=' },
        controller: function($scope, $http) {
        }
    };
});

states.directive('stateMemory', function($http) {
    return {
        templateUrl: '/static/partials/state_memory.html',
        restrict: 'AE',
        scope: { state: '=' },
        controller: function($scope, $http) {
            $scope.start = 0xffff0000 - 1024;
            $scope.limit = 1024;
            $scope.start_input = $scope.start
            $scope.limit_input = $scope.limit

            $scope.sync_start = function() {
		    $scope.start = $scope.start_input;
            	    $scope.limit = $scope.limit_input;
            };
        }
    };
});

states.directive('stateFiles', function($http) {
    return {
        templateUrl: '/static/partials/state_files.html',
        restrict: 'AE',
        scope: { state: '=' },
        controller: function($scope, $http) {
        }
    };
});

states.directive('memoryGrid', function($http) {
    return {
        templateUrl: '/static/partials/memory_grid.html',
        restrict: 'AE',
        scope: { memory: '=', start: '=', limit: '=' },
        controller: function($scope, $http) {
            $scope.get_words = function() {
                var a = [ ];
                for (var i = $scope.start; i < $scope.start + $scope.limit; i++)
                {
                    if (i % 4 == 0) a.push(i);
                }
                return a;
            }

            $scope.get_bytes = function(word) {
                var a = [ word, word + 1, word + 2, word + 3 ]
                return a;
            }
        }
    };
});

states.directive('memoryCell', function($http) {
    return {
        templateUrl: '/static/partials/memory_cell.html',
        restrict: 'AE',
        scope: { concreteValue: '=', addr: '=' },
        controller: function($scope, $http) {
        }
    };
});
