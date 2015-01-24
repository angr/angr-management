var comm = angular.module('angr.comm', []);

comm.factory('newCommunicator', function($rootScope) {
    return function() {
        var comm = $rootScope.$new(true);
        comm.cfgHighlight = {
            registers: {},
            statements: {},
            addresses: {},
            highlights: {},
            exits: {},
            blocks: {},
            tmps: {}
        };
        comm.cfgHighlight2 = {
            registers: {},
            statements: {},
            addresses: {},
            highlights: {},
            exits: {},
            blocks: {},
            tmps: {}
        };
        comm.funcPicker = {
            selected: null
        };
        comm.cfg = {
            expandedStmts: {},
            jumpToBlock: null
        };
        comm.surveyors = {
            viewingSurveyor: null,
            viewingPath: null,
            currentBreakpoint: null,
        };
        comm.graph = {
            delayedFuncs: [],
            layout: function () {},
            centerNode: null
        };
        return comm;
    };
});

comm.factory('globalCommunicator', function ($rootScope) {
    if (!$rootScope.gcomm) {
        var gcomm = $rootScope.$new(true);

        gcomm.useInstance = function (instance) {
            gcomm.funcMan = {
                functions: {},
                edges: [],
                loaded: false,
                findFuncForBlock: function (addr) {
                    for (var key in gcomm.funcMan.functions) {
                        var func = gcomm.funcMan.functions[key];
                        for (var i = 0; i < func.blocks.length; i++) {
                            if (func.blocks[i] == addr) {
                                return func;
                            }
                        }
                    }
                    return null;
                }
            };
            gcomm.arch = {};
            gcomm.irsbs = {};
            gcomm.simProcedures = {};
            gcomm.simProcedureSpots = {};
            gcomm.disasm = {};
            gcomm.surveyors = null;
            gcomm.paths = {};
            gcomm.cfgReady = false;
            gcomm.instance = instance;
            gcomm.labels = {};
        };

        $rootScope.gcomm = gcomm;
    }

    return $rootScope.gcomm;
});

comm.factory('gcomm', function(globalCommunicator) {
    return globalCommunicator;
});
