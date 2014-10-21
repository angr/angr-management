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
        comm.funcPicker = {
            selected: null
        };
        comm.graph = {
            layout: function () {}
        };
        comm.hack = {
            delaybb: [],
            expandedStmts: {}
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
                loaded: false
            };
            gcomm.arch = {};
            gcomm.irsbs = {};
            gcomm.simProcedures = {};
            gcomm.simProcedureSpots = {};
            gcomm.disasm = {};
            gcomm.cfgReady = false;
            gcomm.instance = instance;
        }

        $rootScope.gcomm = gcomm;
    }

    return $rootScope.gcomm;   
});
