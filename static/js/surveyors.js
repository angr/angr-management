var survey = angular.module('angr.surveyors', ['angr.tools']);

survey.controller('AddSurveyorCtrl', function ($scope, $http, $modalInstance, AngrData) {
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
        AngrData.newSurveyor(kwargs).then(function () {
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

survey.directive('surveyors', function surveyors($http, $modal, gcomm) {
    return {
        templateUrl: '/static/partials/surveyors.html',
        restrict: 'AE',
        scope: { data: '=' },
    require: '^workspace',
        controller: function($scope, $http) {
        this.data = $scope.data;
            if (typeof $scope.data.showSur === 'undefined') {
                $scope.data.showSur = {};
            }
            if (typeof $scope.data.showPath === 'undefined') {
                $scope.data.showPath = {};
            }
    },
    link: {pre: function($scope, element, attrs, wk) {
        $scope.gcomm = gcomm;
            $scope.newSurveyor = function () {
                $modal.open({
                    templateUrl: '/static/partials/newsurveyor.html',
                    controller: 'AddSurveyorCtrl'
                }).result.then(function (data) {

                });
            };

        $scope.comm = wk.comm;
        $scope.gcomm = gcomm;
            $scope.$watch('gcomm.paths[comm.surveyors.viewingPath]', function (nv, ov) {
                if (ov && ov.last_addr) {
                    delete wk.comm.cfgHighlight.blocks[ov.last_addr];
                }
                if (ov && ov.split) {
                    wk.comm.cfgHighlight2.blocks = {};    // :(
                }
                if (!nv) {
                    wk.comm.funcPicker.selected = null;
                } else if (nv.split) {
                    for (var i = 0; i < nv.children.length; i++) {
                        wk.comm.cfgHighlight2.blocks[gcomm.paths[nv.children[i]].last_addr] = true;
                    }
                } else {
                    wk.comm.funcPicker.selected = gcomm.funcMan.findFuncForBlock(nv.last_addr);
                    wk.comm.cfgHighlight.blocks[nv.last_addr] = true;
                }
            });
        }}
    };
});

survey.directive('surveyor', function($http, AngrData, gcomm) {
    return {
        templateUrl: '/static/partials/surveyor.html',
        restrict: 'AE',
        scope: {
            sid: '='
        },
    require: '^workspace',
        link: {pre: function($scope, element, attrs, wk) {
            $scope.steps = 1;
        $scope.gcomm = gcomm;
        $scope.$watch('gcomm.surveyors[sid]', function(surveyor) {
        $scope.surveyor = surveyor;
        });
            $scope.step = function(steps) {
                return AngrData.surveyorStep($scope.sid, $scope.steps).then(function(data) {
                    $scope.$broadcast("step");
                    return data;
                });
            };

            $scope.run = function() {
                $scope.step().then(function() {
                    var surveyor = gcomm.surveyors[$scope.sid];
                    if (surveyor.path_lists['active'].length === 0) {
                        return;
                    }
                    var currentBreakpoint = wk.comm.surveyors.currentBreakpoint;
                    for (var i = 0; i < surveyor.path_lists['active'].length; i++) {
                        var pathId = surveyor.path_lists['active'][i];
                        var path = gcomm.paths[pathId];
                        if (path.last_addr === currentBreakpoint) {
                            wk.comm.surveyors.viewingPath = path.id;
                            return;
                        }
                    }
                    $scope.run();
                });
            };

            $scope.reactivate = function(pid) {
                AngrData.pathResume($scope.sid, pid);
            };

            $scope.suspend = function(pid) {
                AngrData.pathSuspend($scope.sid, pid);
            };

        $scope.fetchState = function(pid) {
        AngrData.pathGetState($scope.sid, pid).then(function(data) {
            console.log(data);
        });
        };

            $scope.showCFG = function (pid) {
                AngrData.loadFunctionManager().then(function () {
                    if (!wk.comm.surveyors.viewingPath) {
            wk.addTile({type: 'cfg'});
                    }
                    wk.comm.surveyors.viewingPath = pid;
                    wk.comm.surveyors.viewingSurveyor = $scope.sid;
                });
            };
        }}
    };
});

survey.directive('path', function path($http, gcomm) {
    return {
        templateUrl: '/static/partials/path.html',
        restrict: 'AE',
        scope: { pid: '=', sid: '=' },
    require: '^surveyors',
        link: {pre: function($scope, element, attrs, sv) {
        $scope.showPath = sv.data.showPath;
            $scope.show_path = false;
            $scope.show_events = false;
            $scope.show_backtrace = false;
            $scope.show_state = false;
            $scope.event_limit = 10;
            $scope.backtrace_limit = 10;
            $scope.gcomm = gcomm;
            $scope.$watch('gcomm.paths[pid]', function (nv) {
                $scope.path = gcomm.paths[$scope.pid];
            });
        }}
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
