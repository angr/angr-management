var view = angular.module('angr.view', ['angr.comm', 'angr.tools']);
view.factory('View', function(newCommunicator, globalCommunicator) {

    /* View class
     *
     * @attr root       A reference to the root view that is directly referenced
     *                  by the containing tab
     * @attr parent     A reference to the view directly containing this view. null
     *                  if this is the root view.
     * @attr data       An arbitrary object that is used to store the data needed
     *                  to render and interact with this view via its directive
     * @attr splitData  false if this is a leaf View instead of a spllitting branch
     *                  and a dict {horizontal: bool, size: number} otherwise
     * @attr halfA      null if this is a leaf View; the top/left View of the split
     *                  otherwise.
     * @attr halfB      null if this is a leaf View; the bottom/right View of the
     *                  split otherwise.
     * @attr title      A string. If this is the root View, it will be displayed as
     *                  the tab's name.
     * @attr comm       A basic dict containing all the established communication
     *                  channels
     * @attr gcomm      A dict containing established communication channels that should
     *                  run across tabs.
     */

    /* View Constructor
     *
     * @param data      Either a generic object or a View. If it's a View, the new
     *                  View will be a shallow copy of the argument. Otherwise, the
     *                  argument will become the data parameter of the new View.
     * @param type      A string dictating what directive should be used to render
     *                  this View. Unused if data is a View.
     */

    function View(data, type) {
        this.gcomm = globalCommunicator;
        if (data.constructor === View) {
            this.root = data.root;
            this.parent = data.parent;
            this.data = data.data;
            this.splitData = data.splitData;
            this.halfA = data.halfA;
            this.halfB = data.halfB;
            this.title = data.title;
            this.comm = data.comm;
            this.type = data.type;
        } else {
            this.root = this;
            this.parent = null;
            this.data = data;

            this.splitData = false;
            this.halfA = null;
            this.halfB = null;

            this.title = '';
            this.comm = newCommunicator();
            this.type = type;
        }
    }

    /* View.split(): splits a view into two subviews
     *
     * @param other     a 'root' view that will become the other half of the split
     * @param horz      a bool. true if the splitting is to be done across a
     *                  horizontal line
     * @param size      a number between 0 and 1, the percentage of the way across
     *                  the view the split line is
     * @param which     a bool. true is this view will become the top/left subview,
     *                  false if the 'other' will
     *
     * @returns         a View that is a copy of the original view, suitable to use
     *                  to continue controlling the content that was originally in
     *                  the view.
     */

    View.prototype.split = function (other, horz, size, which) {
        var orig = new View(this);
        this.splitData = {horizontal: horz, size: size};
        this.type = 'SPLIT';
        this.data = {};
        other.parent = this;
        orig.parent = this;
        other.root = this.root;
        other.comm = this.root.comm;
        orig.comm = this.root.comm;
        this.comm = this.root.comm;
        if (which) {
            this.halfA = orig;
            this.halfB = other;
        } else {
            this.halfA = other;
            this.halfB = orig;
        }
        return orig;
    };

    View.prototype.close = function () {
        var p = this.parent;
        if (p) {
            var oc = this.parent.halfA;
            if (oc === this) {
                oc = this.parent.halfB;
            }
            oc.parent = p.parent;
            var r = p.parent;
            if (r) {
                var opc = r.halfA;
                if (r.halfA === p) {
                    r.halfA = oc;
                } else {
                    r.halfB = oc;
                }
            } else {
                p.data = oc.data;
                p.halfA = oc.halfA;
                p.halfB = oc.halfB;
                p.splitData = oc.splitData;
                p.comm = oc.comm;
                p.type = oc.type;
                if (oc.halfA) {
                    oc.halfA.parent = p;
                }
                if (oc.halfB) {
                    oc.halfB.parent = p;
                }
            }
        } else {
            // Closing root of tab!
            console.log('no. why are you doing this.');
        }
    };

    return View;
});
