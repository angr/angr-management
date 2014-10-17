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
        comm.funcMan = {
            functions: {},
            edges: [],
            selected: null,
            loaded: false
        };
        return comm;
    };
});
