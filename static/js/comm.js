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
        comm.graph = {
            layout: function () {}
        };
        comm.hack = {
            delaybb: [],
            expandedStmts: {},
            viewingPath: null
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
            gcomm.surveyors = [];
            gcomm.cfgReady = false;
            gcomm.instance = instance;
        }

        $rootScope.gcomm = gcomm;
    }

    return $rootScope.gcomm;   
});
