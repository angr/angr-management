var workspacesMod = angular.module('angr.workspaces', []);

var layout = function (width, height, tiles) {
    var	nTiles = tiles.length;
    if (nTiles === 1) {
	return [{
	    width: width,
	    height: height,
	    x: 0,
	    y: 0
	}];
    }

    var out = [],
	secondaryWidth = width / 3,
	primaryWidth = width - secondaryWidth,
	secondaryHeight = height / (nTiles - 1),
	numSecondary = 0;
    for (var i = 0; i < nTiles; i++) {
	if (tiles[i].primary) {
	    out.push({
		width: primaryWidth,
		height: height,
		x: secondaryWidth,
		y: 0
	    });
	} else {
            out.push({
		width: secondaryWidth,
		height: secondaryHeight,
		x: 0,
		y: numSecondary * secondaryHeight
            });
	    numSecondary++;
	}
    }
    return out;
};

workspacesMod.directive('workspace', function workspace(Schedule, $window) {
    return {
        restrict: 'E',
        scope: {
	    tiles: '=',
	    uictx: '='
	},
        templateUrl: '/static/partials/workspace.html',
        controller: function ($scope, newCommunicator) {
            $scope.size = [0, 0];
	    this.comm = newCommunicator();
	    this.addTile = function (t) {
		$scope.tiles.push(t);
		$scope.layout();
	    };
	    this.makeTilePrimary = function(tId) {
		$scope.tiles.forEach(function(t) {
		    if (t.id === tId) {
			t.primary = true;
		    } else {
			t.primary = false;
		    }
		});
		$scope.layout();
	    };
        },
	controllerAs: 'wk',
        link: function (scope, element) {
	    scope.tiles.forEach(function(t) {
		t.primary = t.primary || false;
		t.id = t.id || Math.floor(Math.random() * 0x100000).toString();
		t.data = t.data || {};
		t.width = t.width || 0;
		t.height = t.height || 0;
	    });
	    if (scope.tiles.every(function(t) { return !t.primary; })
	       && scope.tiles.length > 0) {
		scope.tiles[0].primary = true;
	    }
	    scope.layout = function() {
		element.css('position', 'relative');
		scope.size = [element.prop('offsetWidth'),
                              element.prop('offsetHeight')];
		var laidOut = layout(scope.size[0], scope.size[1], scope.tiles);
		for (var i = 0; i < scope.tiles.length; i++) {
                    angular.extend(scope.tiles[i], laidOut[i]);
		}
	    };
	    Schedule(scope.layout);
	    angular.element($window).bind('resize', function() {
		scope.layout();
		scope.$apply();
	    });
        }
    };
});
