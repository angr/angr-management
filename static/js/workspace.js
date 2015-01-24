var workspacesMod = angular.module('angr.workspaces', []);

var layout = function (width, height, nTiles) {
    var out = [];
    for (var i = 0; i < nTiles; i++) {
        out.push({
            width: Math.floor(width / nTiles),
            height: height,
            x: Math.floor(width * i / nTiles),
            y: 0
        });
    }
    return out;
};

workspacesMod.directive('workspace', function(Schedule) {
    return {
        restrict: 'E',
        scope: {
	    tiles: '=',
	},
        templateUrl: '/static/partials/workspace.html',
        controller: function ($scope, newCommunicator) {
	    $scope.tiles.forEach(function(t) {
		t.data = t.data || {};
		t.width = t.width || 0;
		t.height = t.height || 0;
	    });
            $scope.size = [0, 0];
	    this.comm = newCommunicator();
	    this.addTile = function (t) {
		$scope.tiles.push(t);
		$scope.layout();
	    };
        },
	controllerAs: 'wk',
        link: function (scope, element) {
	    scope.layout = function() {
		element.css('position', 'relative');
		scope.size = [element.prop('offsetWidth'),
                              element.prop('offsetHeight')];
		var laidOut = layout(scope.size[0], scope.size[1], scope.tiles.length);
		for (var i = 0; i < scope.tiles.length; i++) {
                    angular.extend(scope.tiles[i], laidOut[i]);
		}
	    };
	    Schedule(scope.layout);
	    window.addEventListener('resize', scope.layout);
        }
    };
});
