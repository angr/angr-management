var tilesMod = angular.module('angr.tiles', ['angr.context']);

tilesMod.directive('tile', function ($compile, Context) {
    return {
	    restrict: 'E',
	    require: '^workspace',
	    scope: {
	        tileData: '=',
	        parentUictx: '=',
	        type: '@',
	        tileId: '@'
	    },
	    template: '',
	    controller: function($scope) { this.scope = $scope; },
	    link: {pre: function (scope, element, attrs, wk) {	    
	        var interactionActions = new Context.Actions({children: [{
                    name: 'Make tile primary',
                    action: function () {
		        wk.makeTilePrimary(scope.tileId);
		    },
                    keyboardShortcut: '+p' // this a horrible shortcut, but I can't think of anything better...
                }]});
	        var interactionController = function () {
                    var pos = $(element).parent().position();
                    return {
                        coordinates: new Context.Point(pos.left, pos.top),
                        actions: interactionActions,
                    };
	        };
	        scope.uictx = new Context.Interactable(scope.parentUictx, $(element), interactionController, 'WORKSPACE');
	        var compiled = $compile('<' + scope.type + ' uictx="uictx" data="tileData"></' + scope.type + '>');
	        var applied = compiled(scope);
	        element.append(applied);
	    }},
    };
});
