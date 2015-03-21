var explore = angular.module('angr.explore', ['angr.tools']);

explore.directive('paths', function(AngrData) {
    return {
        templateUrl: '/static/partials/paths.html',
        restrict: 'E',
        scope: { data: '=' },
        require: '^workspace',
        link: {pre: function($scope, element, attrs, wk) {
            $scope.popupStyle = {
                display: 'none',
                position: 'fixed',
                left: '0px',
                top: '0px'
            };

            $scope.newPath = function(e) {
                $scope.popupStyle.display = $scope.popupStyle.display == 'none' ? 'block' : 'none';
                var rect = e.target.getBoundingClientRect();
                $scope.popupStyle.left = rect.left + 'px';
                $scope.popupStyle.top = rect.bottom + 'px';
            };

            $scope.newPathFromEntry = function() {
                $scope.popupStyle.display = 'none';
                AngrData.newPath({type: 'entry_point'}).then(function(path) {
                    $scope.data.active.push(path);
                });
            };

            $scope.stepPath = function(i, pid) {
                AngrData.stepPath(pid, 1).then(function(data) {
                    var args = [i, 1].concat(data);
                    Array.prototype.splice.apply($scope.data.active, args);
                });
            };
        }},
    };
});
