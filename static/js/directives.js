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

dirs.directive('surveyors', function($http) {
    return {
        templateUrl: '/static/partials/surveyors.html',
        restrict: 'AE',
        scope: { project: '=' },
        controller: function($scope, $http)
        {
        	$scope.surveyor_type = "Explorer";
        	$scope.surveyor_options = { };

        	$scope.surveyor_options['find'] = "( )";
        	$scope.surveyor_options['avoid'] = "( )";
        	$scope.surveyor_options['restrict'] = "( )";
        	$scope.surveyor_options['min_depth'] = "1";
        	$scope.surveyor_options['max_repeats'] = "10";
        	$scope.surveyor_options['num_find'] = "1";
        	$scope.surveyor_options['num_avoid'] = "1000000";
        	$scope.surveyor_options['num_deviate'] = "1000000";
        	$scope.surveyor_options['num_loop'] = "1000000";

        	$scope.options = {
        		Explorer: {
        			find: 'Addresses to find (Python expression)',
        			avoid: 'Addresses to avoid (Python expression)',
        			restrict: 'Addresses to restrict the analysis to (Python expression)',
        			min_depth: 'The minimum number of blocks in a path before it can be culled',
        			max_repeats: 'The maximum repeats for a single block before a path is marked as "looping"',
        			num_find: 'Maximum number of paths to find before suspending the analysis',
        			num_avoid: 'Maximum number of paths to avoid before suspending the analysis',
        			num_deviate: 'Maximum number of paths to stop from deviating before suspending the analysis',
        			num_loop: 'Maximum number of paths to stop from looping before suspending the analysis',
        		}
        	}

        	$scope.new_surveyor = function(type, options) {
        		var kwargs = { };
        		if (type == "Explorer")
			{
				kwargs['find'] = "PYTHON:"+options['find'];
				kwargs['avoid'] = "PYTHON:"+options['avoid'];
				kwargs['restrict'] = "PYTHON:"+options['restrict'];
				if (options['min_depth'] != undefined) kwargs['min_depth'] = parseInt(options['min_depth']);
				if (options['max_depth'] != undefined) kwargs['max_depth'] = parseInt(options['max_depth']);
				if (options['max_repeats'] != undefined) kwargs['max_repeats'] = parseInt(options['max_repeats']);
				if (options['num_find'] != undefined) kwargs['num_find'] = parseInt(options['num_find']);
				if (options['num_avoid'] != undefined) kwargs['num_avoid'] = parseInt(options['num_avoid']);
				if (options['num_deviate'] != undefined) kwargs['num_deviate'] = parseInt(options['num_deviate']);
				if (options['num_loop'] != undefined) kwargs['num_loop'] = parseInt(options['num_loop']);
			}

        		$http.post("/api/projects/" + $scope.project.name + "/surveyors/new/"+type, {kwargs:kwargs}).success(function(data, status) {
				$scope.surveyors.push(data);
			});
        	}

                $scope.surveyors = [ ];
                $http.get("/api/projects/" + $scope.project.name + "/surveyors").success(function(data, status) { $scope.surveyors = data; });

                $scope.surveyor_types = [ ];
                $http.get("/api/surveyor_types").success(function(data, status) { $scope.surveyor_types = data; });
        }
    }
});

dirs.directive('surveyor', function($http) {
    return {
        templateUrl: '/static/partials/surveyor.html',
        restrict: 'AE',
        scope: { sid: '=', project: "=", surveyor: '=data' },
        controller: function($scope, $http)
        {
        	if ($scope.surveyor == undefined)
		{
			$http.get("/api/projects/" + $scope.project.name + "/surveyors/" + $scope.sid).success(function(data, status) {
				$scope.surveyor = data;
			});
		}

		$scope.steps = 1;
		$scope.step = function(steps) {
			$http.post("/api/projects/" + $scope.project.name + "/surveyors/" + $scope.sid + "/step", {steps: steps}).success(function(data, status) {
				$scope.surveyor = data;
			});
		}

		$scope.reactivate = function(path) {
			$http.post("/api/projects/" + $scope.project.name + "/surveyors/" + $scope.sid + "/resume/" + path.id).success(function(data, status) {
				$scope.surveyor = data;
			});
		}

		$scope.suspend = function(path) {
			$http.post("/api/projects/" + $scope.project.name + "/surveyors/" + $scope.sid + "/suspend/" + path.id).success(function(data, status) {
				$scope.surveyor = data;
			});
		}
        }
    }
});
