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
    };


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
            if (typeof $scope.view.data.showSur === 'undefined') {
                $scope.view.data.showSur = {};
            }
            if (typeof $scope.view.data.showPath === 'undefined') {
                $scope.view.data.showPath = {};
            }
            $scope.newSurveyor = function () {
                $modal.open({
                    templateUrl: '/static/partials/newsurveyor.html',
                    controller: 'AddSurveyorCtrl'
                }).result.then(function (data) {
                    
                });
            };

            $scope.$watch('view.gcomm.paths[view.comm.hack.viewingPath]', function (nv, ov) {
                if (!nv) {
                    $scope.view.comm.funcPicker.selected = null;
                } else {
                    $scope.view.comm.funcPicker.selected = $scope.view.gcomm.funcMan.findFuncForBlock(nv.last_addr);
                }
            });

        }
    };
});

survey.directive('surveyor', function($http, View, AngrData) {
    return {
        templateUrl: '/static/partials/surveyor.html',
        restrict: 'AE',
        scope: {
            sid: '=',
            view: "="
        },
        controller: function($scope, $http) {
            $scope.view.data.steps = 1;
            $scope.step = function(steps) {
                AngrData.surveyorStep($scope.sid, $scope.view.data.steps, function () {});
            };

            $scope.reactivate = function(pid) {
                AngrData.pathResume($scope.sid, pid, function () {});
            };

            $scope.suspend = function(pid) {
                AngrData.surveyorSuspend($scope.sid, pid, function () {});
            };

            $scope.showCFG = function (pid) {
                AngrData.loadFunctionManager(function () {
                    if (!$scope.view.comm.hack.viewingPath) {
                        var rv = $scope.view.root;
                        rv.split(new View({}, 'CFG'), false, 0.5, true);
                    }
                    $scope.view.comm.hack.viewingPath = pid;
                });
            };
        }
    };
});

survey.directive('path', function($http) {
    return {
        templateUrl: '/static/partials/path.html',
        restrict: 'AE',
        scope: { pid: '=', view: '=' },
        controller: function($scope, $http) {
            $scope.show_path = false;
            $scope.show_events = false;
            $scope.show_backtrace = false;
            $scope.event_limit = 10;
            $scope.backtrace_limit = 10;
            $scope.$watch('view.gcomm.paths[pid]', function (nv) {
                $scope.path = $scope.view.gcomm.paths[$scope.pid];
            });
        }
    };
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
    };
});

survey.directive('address', function($http) {
    return {
        templateUrl: '/static/partials/address.html',
        restrict: 'AE',
        scope: { address: '=a' },
        controller: function($scope, $http) {
            $scope.isNaN = isNaN;
        }
    };
});

survey.directive('ref', function($http) {
    return {
        templateUrl: '/static/partials/ref.html',
        restrict: 'AE',
        scope: { ref: '=data' },
        controller: function($scope, $http) {
        }
    };
});

