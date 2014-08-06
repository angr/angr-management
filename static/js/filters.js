'use strict';

var filts = angular.module('angr.filters', []);

filts.filter('skip', function () {
    return function (arr, count) {
        if (!(arr instanceof Array)) { return arr; }
        if (count < 0) count = 0;
        return arr.slice(count);
    }
});

