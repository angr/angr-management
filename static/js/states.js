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

            // for ASTs, later
            this.scope = $scope;
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

states.directive('memoryCell', function($http, Context) {
    return {
        templateUrl: '/static/partials/memory_cell.html',
        restrict: 'AE',
        require: [ '^tile', '^state' ],
        scope: { concreteValue: '=', memoryObject: '=', addr: '=' },
        link: function($scope, element, attrs, reqs) {
            //
            // menu
            //
            var interactionActions = new Context.Actions({children: [{
                name: 'Display AST',
                action: function() {
                    $scope.displayAST();
                },
                keyboardShortcut: '+d',
            }]});

            var interactionController = function () {
                var pos = $(element).parent().parent().position();
                return {
                    coordinates: new Context.Point(pos.left, pos.top),
                    actions: interactionActions,
                    doubleClick: function () {$scope.toggle();}
                };
            };

            $scope.myuictx = new Context.Interactable(reqs[0].scope.uictx, $(element).parent(), interactionController, 'MEMORY_CELL');
            this.state_scope = reqs[1].scope;
        },
        controller: function($scope, $modal) {
            //
            // AST display modal
            //
            $scope.displayAST = function() {
                $modal.open({
                    templateUrl: '/static/partials/ast_modal.html',
                    controller: 'AstModal',
                    resolve: {
                        memoryObject: function() {
                            return this.state_scope.state.plugins.memory.mem.getMemoryObject($scope.addr);
                        },
                        addr: function() { return $scope.addr; },
                        concreteValue: function() { return $scope.concreteValue; },
                        state: function() { return this.state_scope.state; },
                    }
                });
            };
        },
    };
});

states.directive('ast', function(RecursionHelper) {
    return {
        templateUrl: '/static/partials/ast.html',
        restrict: 'E',
        scope: {
            ast: '=',
            parens: '=',
        },
        compile: RecursionHelper.compile,
        require: '^state',
        controller: function($scope, $http) {
            $scope.ops = {
                __add__: "+", __sub__: "-", __div__: "/", __truediv__: "/", __mul__: "*", __mod__: "%",
                __eq__: "==", __ne__: "!=", __ge__: ">=", __gt__: ">", __le__: "<=", __lt__: "<",
                __neg__: "-", __or__: "|", __and__: "&", __xor__: "^", __invert__: "~",
                __lshift__: "<<", __rshift__: ">>"
            };
        }
    };
});

states.controller('AstModal', function ($scope, $http, $modalInstance, AngrData, memoryObject, addr, concreteValue, state) {
    console.log(state);
    //$scope.close = function() { $modalInstance.dismiss("Closed"); }
    $scope.state = state;
    $scope.memoryObject = memoryObject;
    $scope.addr = addr;
    if (concreteValue != undefined) $scope.concrete = concreteValue.v;
    else $scope.concrete = 0;
});
