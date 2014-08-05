'use strict';

var dirs = angular.module('angr.directives', []);
dirs.directive('newproject', function() {
    return {
        templateUrl: '/static/partials/newproject.html',
        restrict: 'AE',
        controller: function($scope, $http) {
            $scope.project = {};
            $scope.project.name = "my_cool_binary";
            $scope.project.file = null;
            $scope.create = function() {
                var config = {
                    url: '/api/projects',
                    method: 'POST',
                    headers: {
                        'Content-Type': undefined
                    },
                    data: (function() {
                        var formData = new FormData();
                        formData.append('metadata', JSON.stringify($scope.project));
                        formData.append('file', $scope.project.file);
                        console.log($scope.file);
                        return formData;
                    })(),
                    transformRequest: function(formData) { return formData; }
                };
                $http(config).success(function() {
                    alert('project created!');
                }).error(function() {
                    alert('could not create project :(');
                });
            };
        }
    };
});

dirs.directive('loadfile', function($http) {
    return {
        templateUrl: '/static/partials/loadfile.html',
        restrict: 'AE',
        scope: {
            file: '=',
        },
        link: function(scope, element, attrs) {
            scope.chosenURL = null;
            scope.uploadURL = function() {
                var url;
                if (scope.chosenURL.indexOf("http://") === 0) {
                    url = scope.chosenURL.slice(7);
                } else if (scope.chosenURL.indexOf("https://") === 0) {
                    url = scope.chosenURL.slice(8);
                } else {
                    return;
                }
                console.log("http://www.corsproxy.com/" + url);
                $http({
                    method: 'GET',
                    url: "http://www.corsproxy.com/" + url,
                    responseType: "blob",
                    transformResponse: function(data) { return data; }
                }).success(function(data) {
                    scope.file = data;
                });
            };

            var blankHandler = function(e) {
                e.preventDefault();
                e.stopPropagation();
                return false;
            };

            element.bind('dragover', blankHandler);
            element.bind('dragenter', blankHandler);

            element.bind('drop', function(event) {
                event.preventDefault();
                var file = event.dataTransfer.files[0];
                console.log(file);

                var reader = new FileReader();
                reader.onload = function(e) {
                    scope.$apply(function() {
                        scope.file = new Blob([e.target.result]);
                    });
                };
                reader.readAsArrayBuffer(file);

                return false;
            });
        }
    };
});
