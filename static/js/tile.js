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
	link: {pre: function (scope, element, attrs, wk) {	    
	    var interactionActions = new Context.Actions({children: [{
                name: 'Make tile primary',
                action: function () {
		    wk.makeTilePrimary(scope.tileId);
		},
                keyboardShortcut: '+p' // this a horrible shortcut, but I can't think of anything better...
            }, {
                name: 'would be cool if this did something',
                action: function () {alert('EVERYTHING IS COOL WHEN YOU\'RE PART OF A TEAM');},
                keyboardShortcut: 'S+E'
            }, {
                name: 'woaaaahh',
                children: [{
                    name: 'Option 1a',
                    action: function () {alert('option 1a pressed');}
                },{
                    name: 'Option 1b',
                    action: function () {alert('option 1b pressed');}
                }]
            }]});
	    var interactionController = function () {
                var pos = $(element).parent().position();
                return {
                    coordinates: new Context.Point(pos.left, pos.top),
                    actions: interactionActions,
                    doubleClick: function () {alert('DO A DOUBLE CLICK\n\nPRESS Z OR R TWICE');}
                };
	    };
	    scope.uictx = new Context.Interactable(scope.parentUictx, $(element), interactionController, 'WORKSPACE');
	    var compiled = $compile('<' + scope.type + ' uictx="uictx" data="tileData"></' + scope.type + '>');
	    var applied = compiled(scope);
	    element.append(applied);
	}},
    };
});
