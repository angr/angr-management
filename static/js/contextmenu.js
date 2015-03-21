var context = angular.module('angr.context', []);
context.factory('Context', function ($document, $rootScope, globalCommunicator) {
    
    /* class Interactable
     *
     * Represents a UI component that can be right-clicked and selected.
     * Has a parent and children to form a tree of components
     * Each Interacatable instance can report the actions that can be done to it
     * On right-click, the tree is traversed leaf-to-root to find the list of
     * context menu options
     *
     * Constructor arguments:
     *  Interactable parent - The parent of the interactable you're currently spawning, or null
     *  JQuery element - The DOM element to set the context-menu, double-click, etc events on
     *  Function controller - a function that returns an object containing all the actions that can be taken on this component
     *  String type - an identifier string to tell if two Interactables are the same kind of component
     *
     * Class properties:
     *  (all the constructor arguments are copied into homonymous properties)
     *  Interactable children[] - the children of this node
     *  
     * Class methods:
     *  void addChild(Interactable child)
     *  Interactable getNearestSiblingOfChild(Interactable child, int direction)
     *  Interactable getNearestSibling(int direction)
     *  Interactable getFarthestChild(int direction)
     *  Point getCoordinates()
     *  Actions getActions()
     *  bool handleDoubleClick(Event e)
     *  bool handleKeyPress(Event e)
     *  bool handleKeyDown(Event e)
     *  bool handleContextMenu(Event e)
     *  
     * Controller should return an object of the following structure:
     * {
     *   coordinates: Point,
     *   actions: Actions,
     *   doubleClick: Function
     * }
     *
     */

    var Interactable = function (parent, element, controller, type) {
        this.parent = parent;
        this.element = element;
        this.controller = controller;
        this.type = type;
        this.children = [];

        if (this.parent) {
            this.parent.addChild(this);
        }

        element[0].tabIndex = 0;
        
        var thiser = this;
        // element.on('contextmenu', function (e) {
        //     if (thiser.handleContextMenu(e)) {
        //         $rootScope.$digest();
        //         e.stopPropagation();
        //         e.preventDefault();
        //     }
        // });
        element.on('dblclick', function (e) {
            if (thiser.handleDoubleClick(e)) {
                $rootScope.$digest();
                e.stopPropagation();
                e.preventDefault();
            }
        });
        element.on('keypress', function (e) {
            if (thiser.handleKeyPress(e)) {
                $rootScope.$digest();
                e.stopPropagation();
                e.preventDefault();
            }
        });
        element.on('keydown', function (e) {
            if (thiser.handleKeyDown(e)) {
                $rootScope.$digest();
                e.stopPropagation();
                e.preventDefault();
            }
        });
        element.on('click', function (e) {
            if (element[0].focus) {     // won't run for document root
                element[0].focus();
                e.stopPropagation();
            }
        });
    };

    Interactable.prototype.addChild = function (child) {
        this.children.push(child);
    };

    // Direction: [Left, Up, Down, Right]
    Interactable.prototype.getNearestSibling = function (direction) {
        if (this.parent === null) return null;
        else return this.parent.getNearestSiblingOfChild(this, direction);
    };

    Interactable.prototype.getNearestSiblingOfChild = function (child, direction) {
        if (child === null) {
            return this.getFarthestChild(direction ^ 3);
        }
        best = null;
        bestDist = null;
        myLocation = child.getCoordinates();
        for (var i = 0; i < this.children.length; i++) {
            if (child === this.children[i]) {
                continue;
            }

            var pCoords = this.children[i].getCoordinates();
            if (myLocation.directionTo(pCoords) !== direction) {
                continue;
            }

            var pDist = myLocation.distanceTo(pCoords);
            if (best === null) {
                best = this.children[i];
                bestDist = pDist;
            } else {
                if (pDist < bestDist) {
                    best = this.children[i];
                    bestDist = pDist;
                }
            }
        }
        if (best === null) {
            var aunt = this.getNearestSibling(direction);
            if (aunt === null) return null;
            if (aunt.type !== this.type) return aunt;
            if (aunt.children.length === 0) return aunt;
            return aunt.getFarthestChild(direction ^ 3);
        }
        return best;
    };

    Interactable.prototype.getFarthestChild = function (direction) {
        best = null;
        bestCoords = null;
        for (var i = 0; i < this.children.length; i++) {
            var theseCoords = this.children[i].getCoordinates();
            if (best === null) {
                best = this.children[i];
                bestCoords = theseCoords;
                continue;
            }
            switch (direction) {
                case 0: // right
                    if (theseCoords.x > bestCoords.x) {
                        best = this.children[i];
                        bestCoords = theseCoords;
                    }
                    break;
                case 1: // up
                    if (theseCoords.y < bestCoords.y) {
                        best = this.children[i];
                        bestCoords = theseCoords;
                    }
                    break;
                case 2: // down
                    if (theseCoords.y > bestCoords.y) {
                        best = this.children[i];
                        bestCoords = theseCoords;
                    }
                    break;
                case 3: // right
                    if (theseCoords.x < bestCoords.x) {
                        best = this.children[i];
                        bestCoords = theseCoords;
                    }
                    break;
                default:
                    break;
            }
        }
        return best;
    };

    Interactable.prototype.getCoordinates = function () {
        return this.controller().coordinates;
    };

    Interactable.prototype.getActions = function () {
        if (this.parent === null) return this.controller().actions;
        else return this.parent.getActions().addActions(this.controller().actions);
    };

    Interactable.prototype.handleDoubleClick = function (e) {
        var a = this.controller().doubleClick;
        if (!a) return false;
        a(e);
        return true;
    };

    Interactable.prototype.handleKeyPress = function (e) {
        if (e.which == 13 && !e.ctrlKey && !e.shiftKey && !e.altKey && this.handleDoubleClick(e)) {
            return true;
        }
        return this.getActions().runKeyboardShortcut(e);
    };

    Interactable.prototype.handleKeyDown = function (e) {
        var t = null;
        if (e.shiftKey) {
            t = {38: this.parent, 40: this.children[0]}[e.keyCode];
        } else {
            t = {37: 0, 38: 1, 40: 2, 39: 3}[e.keyCode];
            if (typeof t === 'number') {
                t = this.getNearestSibling(t);
            }
        }
        if (t) {
            t.element.focus();
            return true;
        }
        return false;
    };

    Interactable.prototype.handleContextMenu = function (e) {
        if (e.ctrlKey) return false;    // Allow system context menus when ctrl key is held
        var actions = this.getActions();
        if (actions.countActive() === 0) return false;
        openMenu(actions, e.pageX, e.pageY);
        return true;
    };

    /* class Point
     *
     * Basically a vector implementation
     * because everyone needs one
     */

    var Point = function (x, y) {
        this.x = x;
        this.y = y;
    };

    Point.prototype.distanceTo = function(that) {
        return Math.sqrt(Math.pow(this.x-that.x, 2) + Math.pow(this.y-that.y, 2));
    };

    // Direction: [Left, Up, Down, Right]
    Point.prototype.directionTo = function(that) {
        var normalized = that.subtract(this);
        var out = 0;
        if (normalized.y > normalized.x)  out += 2;
        if (normalized.y < -normalized.x) out += 1;
        return out;
    };

    Point.prototype.add = function(that) {
        return new Point(this.x+that.x, this.y+that.y);
    };

    Point.prototype.subtract = function (that) {
        return new Point(this.x-that.x, this.y-that.y);
    };

    Point.prototype.scalarMultiply = function (that) {
        return new Point(this.x*that, this.y*that);
    };

    /* class Actions
     *  
     *  Represents a single action that could show up in a context menu (or as a keyboard shortcut)
     *  and all of its children.
     *
     *  Constructor arguments:
     *   Object tree: a bare object with properties that should instanciate the tree. See below for form.
     *
     *  Class properties:
     *   Object tree: The tree from the constructor, with all the children replaced with Actions-s
     *   Object allKeyboardShortcuts: A mapping from keyboard shortcut strings (see format below) to Actions instances
     *   Function action: The actual function to execute, copied to the instance so when it gets run `this` will point to the Actions instance.
     *   Actions[] children: copied from the tree
     *   String name: copied from the tree
     *
     *  Class methods:
     *   void addActions(Actions other): Append the children of other to this instance's children
     *   bool run(): If the action is enabled (via isEnabled), run. Return whether or not it ran.
     *   bool runKeyboardShortcut(Event e): If the passed keyboard event matches one of the keyboard shortcuts registered, run it. Return whether or not something ran.
     *   bool isEnabled()
     *   bool isChecked()
     *   bool shouldDisplay()
     *   int countActive(): Counts the number of children who have shouldDisplay: true
     *
     *  Tree format:
     *   {
     *      name: String,
     *      action: Function,
     *      shouldDisplay: {Function, bool},
     *      isEnabled: {Function, bool},
     *      isChecked: {Function, null},
     *      keyboardShortcut: {String, null},
     *      children: {Actions, Object}[]
     *   }
     *
     *  Keyboard shortcuts are strings in the form /^[CAS]*\+.$/
     *  The character after the plus is the trigger character
     *  C before the plus means hold ctrl
     *  A before the plus means hold alt
     *  S before the plus means hold shift
     *  *** in order to actually match the character reported, the character after the plus 
     *  *** must be entered with capitalization/form according to how the shift key is held
     * 
     *  The root node's information won't actually be displayed anywhere, probably
     *
     */

    var Actions = function (tree) {
        if (typeof tree === 'undefined') tree = {};
        if (typeof tree.isEnabled === 'undefined') tree.isEnabled = true;
        if (typeof tree.shouldDisplay === 'undefined') tree.shouldDisplay = true;
        if (typeof tree.isChecked === 'undefined') tree.isChecked = false;
        if (typeof tree.children === 'undefined') tree.children = [];
        if (typeof tree.keyboardShortcut === 'undefined') tree.keyboardShortcut = null;
        this.tree = tree;
        this.allKeyboardShortcuts = {};
        this.action = tree.action;
        this.children = tree.children;
        this.name = tree.name;

        if (tree.keyboardShortcut !== null) {
            this.allKeyboardShortcuts[tree.keyboardShortcut] = this;
        }

        for (var i = 0; i < this.children.length; i++) {
            if (!Actions.isPrototypeOf(this.children[i])) {
                this.children[i] = new Actions(this.children[i]);
            }
            angular.extend(this.allKeyboardShortcuts, this.children[i].allKeyboardShortcuts);
        }
    };

    Actions.prototype.addActions = function (other) {
        var out = new Actions();
        out.children = this.children.concat(other.children);
        angular.extend(out.allKeyboardShortcuts, this.allKeyboardShortcuts, other.allKeyboardShortcuts);
        return out;
    };

    Actions.prototype.run = function (e) {
        if (this.action && this.isEnabled()) {
            this.action(e);
            return true;
        }
        return false;
    };

    Actions.prototype.runKeyboardShortcut = function (e) {
        var s = '';
        if (e.ctrlKey) s += 'C';
        if (e.shiftKey) s += 'S';
        if (e.altKey) s += 'A';
        s += '+';
        s += String.fromCharCode(e.which);
        if (s in this.allKeyboardShortcuts) {
            return this.allKeyboardShortcuts[s].run();
        }
        return false;
    };

    Actions.prototype.isEnabled = function () {
        return (typeof this.tree.isEnabled === 'function' && this.tree.isEnabled()) || (typeof this.tree.isEnabled !== 'function' && this.tree.isEnabled);
    };

    Actions.prototype.isChecked = function () {
        return (typeof this.tree.isChecked === 'function' && this.tree.isChecked()) || (typeof this.tree.isChecked !== 'function' && this.tree.isChecked);
    };

    Actions.prototype.shouldDisplay = function () {
        return (typeof this.tree.shouldDisplay === 'function' && this.tree.shouldDisplay()) || (typeof this.tree.shouldDisplay !== 'function' && this.tree.shouldDisplay);
    };

    Actions.prototype.countActive = function () {
        var out = 0;
        for (var i = 0; i < this.children.length; i++) {
            if (this.children[i].shouldDisplay()) out++;
        }
        return out;
    };

    var closeMenu = function () {
        if (!globalCommunicator.contextMenu.active) return;
        var end = function () {
            globalCommunicator.contextMenu.active = false;
            globalCommunicator.contextMenu.actions = null;
        };
        if ($rootScope.$$phase) {
            end();
        } else {
            $rootScope.$apply(end);
        }
        $document.off('click', closeMenu);
    };
    var openMenu = function (actions, x, y) {
        closeMenu();
        globalCommunicator.contextMenu.active = true;
        globalCommunicator.contextMenu.x = x;
        globalCommunicator.contextMenu.y = y;
        globalCommunicator.contextMenu.actions = actions;
        $document.on('click', closeMenu);
    };
    return {
        Interactable: Interactable,
        Point: Point,
        Actions: Actions,
        closeMenu: closeMenu,
        openMenu: openMenu
    };
});

context.directive('contextMenuEndpoint', function (Context, globalCommunicator) {
    return {
        restrict: 'E',
        templateUrl: '/static/partials/contextmenuendpoint.html',
        link: function ($scope, element, attrs) {
            $scope.gcomm = globalCommunicator;
            $scope.currentsub = null;
            $scope.click = function (action, e) {
                e.stopPropagation();
                if (!action.isEnabled()) return;
                if (action.run()) {
                    Context.closeMenu();
                }
            };
            $scope.mouseenter = function (action) {
                if ($scope.currentsub !== null) {
                    $scope.currentsub._showsubs = false;
                }
                action._showsubs = true;
                $scope.currentsub = action;
            };
        }
    };
});

context.directive('contextMenuItem', function (RecursionHelper, Context) {
    return {
        templateUrl: '/static/partials/contextmenuitem.html',
        scope: {
            action: '='
        },
        controller: function ($scope) {
            $scope.currentsub = null;
            $scope.click = function (action, e) {
                e.stopPropagation();
                if (!action.isEnabled()) return;
                if (action.run()) {
                    Context.closeMenu();
                }
            };
            $scope.mouseenter = function (action) {
                if ($scope.currentsub !== null) {
                    $scope.currentsub._showsubs = false;
                }
                action._showsubs = true;
                $scope.currentsub = action;
            };
        },
        compile: RecursionHelper.compile
    };
});

context.directive('hardFocusable', function () {
    return {
        link: function ($scope, element, attrs) {
            var idgaf = function (e) {
                e.stopPropagation();
            };
            var el = jQuery(element);
            el.click(idgaf);
            el.keydown(idgaf);
            el.dblclick(idgaf);
            el.keypress(idgaf);
        }
    };  
});
