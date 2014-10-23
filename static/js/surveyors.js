var survey = angular.module('angr.surveyors', ['angr.tools']);

survey.controller('AddSurveyorCtrl', function ($scope, $http, $modalInstance, View, AngrData) {
    $scope.thinking = false;

    $scope.cancel = function () {
        $modalInstance.dismiss("Canceled");
    };

    $scope.add = function () {
        var kwargs = { };
        var flds = $scope.surveyorFields;  // brevity
        kwargs['find'] = "PYTHON:"+flds['find'];
        kwargs['avoid'] = "PYTHON:"+flds['avoid'];
        kwargs['restrict'] = "PYTHON:"+flds['restrict'];
        if (flds['min_depth'] != undefined) kwargs['min_depth'] =     parseInt(flds['min_depth']);
        if (flds['max_depth'] != undefined) kwargs['max_depth'] =     parseInt(flds['max_depth']);
        if (flds['max_repeats'] != undefined) kwargs['max_repeats'] = parseInt(flds['max_repeats']);
        if (flds['num_find'] != undefined) kwargs['num_find'] =       parseInt(flds['num_find']);
        if (flds['num_avoid'] != undefined) kwargs['num_avoid'] =     parseInt(flds['num_avoid']);
        if (flds['num_deviate'] != undefined) kwargs['num_deviate'] = parseInt(flds['num_deviate']);
        if (flds['num_loop'] != undefined) kwargs['num_loop'] =       parseInt(flds['num_loop']);

        kwargs['type'] = $scope.surveyorType;

        $scope.thinking = true;
        AngrData.newSurveyor(kwargs, function () {
            $scope.thinking = false;
            $modalInstance.close();
        }, function (data) {
            alert(data.message);
            $scope.thinking = false;
        });
    }


    $scope.surveyorType = "Explorer";
    $scope.surveyorTypes = ['Explorer', 'Executor', 'Escaper', 'Slicecutor'];
    $scope.surveyorFields = { };

    $scope.surveyorFields['find'] = "( )";
    $scope.surveyorFields['avoid'] = "( )";
    $scope.surveyorFields['restrict'] = "( )";
    $scope.surveyorFields['min_depth'] = "1";
    $scope.surveyorFields['max_repeats'] = "10";
    $scope.surveyorFields['num_find'] = "1";
    $scope.surveyorFields['num_avoid'] = "1000000";
    $scope.surveyorFields['num_deviate'] = "1000000";
    $scope.surveyorFields['num_loop'] = "1000000";

    $scope.surveyorFieldDescriptions = {
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
    };
});

survey.directive('surveyors', function($http, $modal) {
    return {
        templateUrl: '/static/partials/surveyors.html',
        restrict: 'AE',
        scope: { view: '=' },
        controller: function($scope, $http) {
            $scope.newSurveyor = function () {
                $modal.open({
                    templateUrl: '/static/partials/newsurveyor.html',
                    controller: 'AddSurveyorCtrl'
                }).result.then(function (data) {
                    
                });
            };

            $scope.$watch('view.comm.hack.viewingPath', function (nv, ov) {
                if (!nv) {
                    $scope.view.comm.funcPicker.selected = null;
                } else {
                    $scope.view.comm.funcPicker.selected = $scope.view.gcomm.funcMan.findFuncForBlock(nv.last_addr);
                }
            });

        }
    }
});

survey.directive('surveyor', function($http, View) {
    return {
        templateUrl: '/static/partials/surveyor.html',
        restrict: 'AE',
        scope: {
            sid: '=',
            view: "=",
            surveyor: '=data'
        },
        controller: function($scope, $http) {
            $scope.console = console
            $scope.show_surveyor = false;
            if ($scope.surveyor == undefined)
            {
                $http.get("/api/instances/" + $scope.instance + "/surveyors/" + $scope.sid).success(function(data, status) {
                    $scope.surveyor = data;
                });
            }

            $scope.steps = 1;
            $scope.step = function(steps) {
                $http.post("/api/instances/" + $scope.instance + "/surveyors/" + $scope.sid + "/step", {steps: steps}).success(function(data, status) {
                    var old_pid = $scope.view.comm.hack.viewingPath;
                    if (old_pid) old_pid = old_pid.id;
                    $scope.surveyor = data;
                    if (old_pid) {
                        var found = false;
                        for (var path_name in data.path_lists) {
                            for (var i = 0; i < data.path_lists[path_name].length; i++) {
                                if (old_pid == data.path_lists[path_name][i].id) {
                                    $scope.view.comm.hack.viewingPath = data.path_lists[path_name][i];
                                    found = true;
                                    break;
                                }
                            }
                            if (found) break;
                        }
                        if (!found) {
                            $scope.view.comm.hack.viewingPath = null;
                            $scope.view.root.halfB.close();
                        }
                    }
                });
            };

            $scope.reactivate = function(path) {
                $http.post("/api/instances/" + $scope.instance + "/surveyors/" + $scope.sid + "/resume/" + path.id).success(function(data, status) {
                    $scope.surveyor = data;
                });
            };

            $scope.suspend = function(path) {
                $http.post("/api/instances/" + $scope.instance + "/surveyors/" + $scope.sid + "/suspend/" + path.id).success(function(data, status) {
                    $scope.surveyor = data;
                });
            };

            $scope.showCFG = function (path) {
                if (!$scope.view.comm.hack.viewingPath) {
                    var rv = $scope.view.root;
                    rv.split(new View({}, 'CFG'), false, 0.5, true);
                }
                $scope.view.comm.hack.viewingPath = path;
            };
        }
    }
});

survey.directive('path', function($http) {
    return {
        templateUrl: '/static/partials/path.html',
        restrict: 'AE',
        scope: { path: '=data' },
        controller: function($scope, $http) {
            $scope.show_path = true;
            $scope.show_events = false;
            $scope.show_backtrace = false;
            $scope.event_limit = 10;
            $scope.backtrace_limit = 10;
        }
    }
});

survey.directive('event', function($http) {
    return {
        templateUrl: '/static/partials/path_event.html',
        restrict: 'AE',
        scope: { event: '=data' },
        controller: function($scope, $http) {
            $scope.show_refs = false;
            $scope.show_event = false;
        }
    }
});

survey.directive('address', function($http) {
    return {
        templateUrl: '/static/partials/address.html',
        restrict: 'AE',
        scope: { address: '=a' },
        controller: function($scope, $http) {
            $scope.isNaN = isNaN;
        }
    }
});

survey.directive('ref', function($http) {
    return {
        templateUrl: '/static/partials/ref.html',
        restrict: 'AE',
        scope: { ref: '=data' },
        controller: function($scope, $http) {
        }
    }
});

