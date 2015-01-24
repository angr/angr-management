var tilesMod = angular.module('angr.tiles', []);

tilesMod.directive('tile', function ($compile) {
    return {
	restrict: 'E',
	// not required for now
	// require: '^workspace',
	scope: {
	    tileData: '=',
	    type: '@',
	},
	template: '',
	link: function (scope, element) {
	    var compiled = $compile('<' + scope.type + ' data="tileData"></' + scope.type + '>');
	    var applied = compiled(scope);
	    element.append(applied);
	},
    };
});
