var contextMenuData = []; // John can kill me for this later -- indeed
var activeScope = null;

var contextMenu = angular.module('angr.contextMenu', []);
contextMenu.factory('ContextMenu', function ($document) {
    var registerEntries = function (element, callback) {
        element.on('contextmenu', function () {
            //console.log('node');
            contextMenuData.push(callback);
        });
    };
    var closeMenu = function () {
        if (activeScope === null) return;
        var end = function () {
            activeScope.active = false;
            activeScope = null;
        };
        if (activeScope.$$phase) {
            end();
        } else {
            activeScope.$apply(end);
        }
        $document.off('click', closeMenu);
    };
    var openMenu = function (scope, x, y) {
        closeMenu();
        scope.items = [];
        for (var i = 0; i < contextMenuData.length; i++) {
            scope.items = scope.items.concat(contextMenuData[i]());
        }
        contextMenuData = [];
        scope.active = true;
        scope.position.x = x;
        scope.position.y = y;
        activeScope = scope;
        $document.on('click', closeMenu);
    };
    return {
        registerEntries: registerEntries,
        closeMenu: closeMenu,
        openMenu: openMenu
    };
});

contextMenu.directive('contextMenuEndpoint', function (ContextMenu) {
    return {
        restrict: 'E',
        templateUrl: '/static/partials/contextmenuendpoint.html',
        link: function ($scope, element, attrs) {
            $scope.active = false;
            $scope.items = [];
            $scope.position = {x: 0, y: 0};
            $scope.currentsub = null;
            element.parent().on('contextmenu', function (e) {
                e.stopPropagation();
                e.preventDefault();
                //console.log('hit endpoint');
                $scope.$apply(function () {
                    ContextMenu.openMenu($scope, e.pageX, e.pageY);
                });
                return false;
            });
            $scope.click = function (item, e) {
                e.stopPropagation();
                if (item.disabled) return;
                if (typeof item.action !== 'function') return;
                item.action();
                ContextMenu.closeMenu();
            };
            $scope.mouseenter = function (item) {
                if ($scope.currentsub !== null) {
                    $scope.currentsub._showsubs = false;
                }
                item._showsubs = true;
                $scope.currentsub = item;
            };
        }
    };
});

contextMenu.directive('contextMenuItem', function (RecursionHelper, ContextMenu) {
    return {
        templateUrl: '/static/partials/contextmenuitem.html',
        scope: {
            item: '='
        },
        controller: function ($scope) {
            $scope.currentsub = null;
            $scope.click = function (item, e) {
                e.stopPropagation();
                if (item.disabled) return;
                if (typeof item.action !== 'function') return;
                item.action();
                ContextMenu.closeMenu();
            };
            $scope.mouseenter = function (item) {
                if ($scope.currentsub !== null) {
                    $scope.currentsub._showsubs = false;
                }
                item._showsubs = true;
                $scope.currentsub = item;
            };
        },
        compile: RecursionHelper.compile
    };
});
