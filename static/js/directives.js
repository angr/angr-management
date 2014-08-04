'use strict';

var dirs = angular.module('angr.directives', []);
dirs.directive('loadFile', function() {
    return {
        templateUrl: '/static/partials/loadfile.html',
        restrict: 'AE',
        scope: {
            file: '=',
            filename: '=',
        },
        link: function(scope, element, attrs) {
            var blankHandler = function(e) {
                e.preventDefault();
                e.dataTransfer.effectAllowed = 'copy';
                return false;
            };

            element.bind('dragover', blankHandler);
            element.bind('dragenter', blankHandler);

            element.bind('drop', function(event) {
                event.preventDefault();
                var file = event.dataTransfer.files[0];

                var reader = new FileReader();
                reader.onload = function(e) {
                    scope.$apply(function() {
                        scope.file = e.target.result;
                        scope.fileName = file.name;
                    });
                };
                reader.readAsDataURL(file);

                return false;
            });
        }
    };
});
