'use strict';

var ctrls = angular.module('angr.controllers', ['dialogs.main', 'angr.tiles', 'angr.workspaces', 'angr.surveyors', 'angr.context', 'angr.states']);

ctrls.controller('IndexCtrl', function($scope, $http, projects) {
    $scope.projects = projects;
});

ctrls.controller('ProjectCtrl', function($scope, $document, $http, $routeParams, $interval, $modal, AngrData, Context) {
    $scope.inst_id = $routeParams['inst_id'];
    $scope.instance = {};
    $http.get('/api/instances/' + $scope.inst_id).success(function (data) {
        if (data.success) {
            $scope.instance = data;
            AngrData.gcomm.useInstance(data.id);
            AngrData.gcomm.arch = data.arch;
        } else {
            alert(data.message);
        }
    }, function () {
        alert('Something bad happened while pinging the instance...');
    });
    $scope.tabSpaceStyle = {
	display: 'block',
        position: 'relative',
        left: '0px',
        right: '0px',
	// width: '100%',
	height: '100%',
	top: '0px',
	bottom: '0px'
    };

    // not ready yet...
    // if (prevState !== null) {
    //     $scope.tabs = prevState;
    // } else {
    //     $scope.tabs = [];
    // }

    // $interval(function () {
    //     saveState($scope.tabs);
    // }, 1000);

    $scope.tabs = [];
    $scope.activeTab = -1;

    $scope.popupStyle = {
        display: 'none',
        position: 'fixed',
        left: '0px',
        top: '0px'
    };

    $scope.activateTab = function (tabIndex) {
        $scope.activeTab = tabIndex;
    };

    $scope.addTab = function(tab) {
        $scope.tabs.push(tab);
        $scope.activeTab = $scope.tabs.length - 1;
    };

    $scope.newTab = function (e) {
        $scope.popupStyle.display = $scope.popupStyle.display == 'none' ? 'block' : 'none';
        var rect = e.target.getBoundingClientRect();
        $scope.popupStyle.left = rect.left + 'px';
        $scope.popupStyle.top = rect.bottom + 'px';
    };

    $scope.closeTab = function(tabIndex) {
        $scope.tabs.splice(tabIndex, 1);
        if ($scope.activeTab >= $scope.tabs.length) {
            $scope.activeTab = $scope.tabs.length - 1;
        }
    };

    $scope.newTabs = {
        'Function Overview': function () {
            // var graph = new View({}, 'PROXIMITY_GRAPH');
            // var manager = new View({}, 'FUNCTION_MANAGER');
            // var picker = new View({}, 'FUNCTION_PICKER');
            // picker.split(manager, true, 0.5, true);
            // picker.split(graph, false, 0.2, true);
            // picker.title = 'Functions';
	    var tiles = [{type: 'proxgraph'}, {type: 'funcman'}, {type: 'funcpicker'}];
            $scope.thinking = true;
            $scope.popupStyle.display = 'none';

            AngrData.loadFunctionManager().then(function () {
                $scope.thinking = false;
                $scope.addTab({title: 'Functions', tiles: tiles});
            }, function (data) {
                alert(data.message);
                $scope.thinking = false;
            });
        },
        'CFG': function () {
            // var cfg = new View({}, 'CFG');
            // var manager = new View({}, 'FUNCTION_MANAGER');
            // var picker = new View({}, 'FUNCTION_PICKER');
            // picker.split(manager, true, 0.6, true);
            // picker.split(cfg, false, 0.2, true);
            // picker.title = 'CFG Tab';
	    var tiles = [{type: 'cfg'}, {type: 'funcman'}, {type: 'funcpicker'}];
            $scope.thinking = true;
            $scope.popupStyle.display = 'none';

            AngrData.loadFunctionManager().then(function () {
                $scope.thinking = false;
                $scope.addTab({title: 'CFG', tiles: tiles});
            }, function (data) {
                alert(data.message);
                $scope.thinking = false;
            });
        },
        'Surveyors': function () {
            $scope.popupStyle.display = 'none';
            // var view = new View({}, 'SURVEYOR');
            // view.title = 'Surveyors';
	    var tiles = [{type: 'surveyors'}];

            AngrData.loadSurveyors().then(function () {
                $scope.addTab({title: 'Surveyors', tiles: tiles});
            }, function (data) {
                alert(data.message);
                $scope.thinking = false;
            });
        },
        // 'Splitting Demo': function () {
        //     $scope.popupStyle.display = 'none';
        //     var view = new View({}, 'SPLITTEST');
        //     view.title = 'Split Test';
        //     $scope.addTab(view);
        // }
    };

    var globalActions = new Context.Actions();
    var interactionController = function () {
        return {
            coordinates: new Context.Point(0,0),
            actions: globalActions,
            doubleClick: function () {}
        };
    };
    $scope.uictx = new Context.Interactable(null, $($document), interactionController, 'PROJECT_ROOT');

});


ctrls.controller('UseProjectDialog', function ($scope, $modalInstance, $http, $location) {
    $scope.thinking = false;
    $scope.newInstanceName = '';

    $scope.newInstance = function () {
        $scope.thinking = true;
        $http.post("/api/instances/new/" + $scope.project.name, {name: $scope.newInstanceName}).success(function (data) {
            $scope.thinking = false;
            if (data.success) {
                $scope.project.instances.push({id: data.id, name: $scope.newInstanceName});
                $modalInstance.close();
                $location.path('/instance/' + data.id);
            } else {
                alert(data.message);
            }
        }).error(function (data) {
            $scope.thinking = false;
            alert('Couldn\'t create instance :(')
        });
    };

    $scope.useInstance = function (inst) {
        $modalInstance.close();
        $location.path('/instance/' + inst);
    };

    $scope.cancel = function () {
        $modalInstance.close();
    };
});
