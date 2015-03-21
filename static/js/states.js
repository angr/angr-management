var states = angular.module('angr.states', ['angr.tools']);

states.directive('state', function($http) {
    return {
        templateUrl: '/static/partials/state.html',
        restrict: 'E',
        scope: { pid: '=pid' },
        controller: function($scope, $http, AngrData) {
            $scope.state = null;
            $scope.refreshState = function() {
                AngrData.pathGetState($scope.pid).then(function(data) {
                    $scope.state = data;
                });
            };
            $scope.$on("step", function() {
                $scope.refreshState();
            });

            $scope.refreshState();
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
            $scope.start_value = $scope.start.toString(16)

            $scope.sync_start = function() {
		    $scope.start = Number($scope.start_value);
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
            $scope.count = function(s) {
                var i = 0;
                for (var prop in s) {
                    if (s.hasOwnProperty(prop)) {
                        i += 1;
                    }
                }
                return i;
            };
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
