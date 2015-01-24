'use strict';

var srvcs = angular.module('angr.services', []);
srvcs.factory('Projects', function($http) {
    var projects = $http.get('/api/projects/').then(function(res) { return res.data; });

    return {
        projects: function() { return projects; }
    };
});

srvcs.factory('Status', function() {
    var status = 'All good.';

    return {
        status: function() { return status; },
        setStatus: function(s) { status = s; },
    };
});

srvcs.factory('LayoutCache', function() {
    return {
        cache: {},
    };
});

srvcs.factory('prevState', function () {
    if (localStorage.hasOwnProperty("savedState")) {
        return JSON.parse(localStorage.savedState);
    }
    return null;
});

srvcs.factory('saveState', function () {
    return function (state) {
        localStorage.savedState = JSON.stringify(state);
    };
});

// From http://stackoverflow.com/questions/14430655/recursion-in-angular-directives
srvcs.factory('RecursionHelper', ['$compile', function($compile){
    return {
        /**
         * Manually compiles the element, fixing the recursion loop.
         * @param element
         * @param [link] A post-link function, or an object with function(s) registered via pre and post properties.
         * @returns An object containing the linking functions.
         */
        compile: function(element, link){
            // Normalize the link parameter
            if(angular.isFunction(link)){
                link = { post: link };
            }

            // Break the recursion loop by removing the contents
            var contents = element.contents().remove();
            var compiledContents;
            return {
                pre: (link && link.pre) ? link.pre : null,
                /**
                 * Compiles and re-adds the contents
                 */
                post: function(scope, element){
                    // Compile the contents
                    if(!compiledContents){
                        compiledContents = $compile(contents);
                    }
                    // Re-add the compiled contents to the element
                    compiledContents(scope, function(clone){
                        element.append(clone);
                    });

                    // Call the post-linking function, if any
                    if(link && link.post){
                        link.post.apply(null, arguments);
                    }
                }
            };
        }
    };
}]);
