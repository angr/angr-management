(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
(function (global){
/*
 * Copyright (c) 2012-2013 Chris Pettitt
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
global.graphlibDot = require("./index");

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./index":2}],2:[function(require,module,exports){
var read = require("./lib/read-one"),
    readMany = require("./lib/read-many"),
    write = require("./lib/write-one"),
    version = require("./lib/version");

module.exports = {
  graphlib: require("./lib/graphlib"),

  // Parsing
  read: read,
  readMany: readMany,

  // Writing
  write: write,

  // Version
  version: version,

  // For levelup encoding
  type: "dot",
  buffer: false
};

},{"./lib/graphlib":5,"./lib/read-many":7,"./lib/read-one":8,"./lib/version":9,"./lib/write-one":10}],3:[function(require,module,exports){
"use strict";

var _ = require("./lodash"),
    Graph = require("./graphlib").Graph;

module.exports = buildGraph;

function buildGraph(parseTree) {
  var isDirected = parseTree.type !== "graph",
      isMultigraph = !parseTree.strict,
      defaultStack = [{ node: {}, edge: {} }],
      g = new Graph({ directed: isDirected, multigraph: isMultigraph, compound: true });
      g.setGraph({});
  _.each(parseTree.stmts, function(stmt) { handleStmt(g, stmt, defaultStack); });
  return g;
}

function handleStmt(g, stmt, defaultStack, sg) {
  switch(stmt.type) {
    case "node": handleNodeStmt(g, stmt, defaultStack, sg); break;
    case "edge": handleEdgeStmt(g, stmt, defaultStack, sg); break;
    case "subgraph": handleSubgraphStmt(g, stmt, defaultStack, sg); break;
    case "attr": handleAttrStmt(g, stmt, defaultStack); break;
    case "inlineAttr": handleInlineAttrsStmt(g, stmt, defaultStack, sg); break;
  }
}

function handleNodeStmt(g, stmt, defaultStack, sg) {
  var v = stmt.id,
      attrs = stmt.attrs;
  maybeCreateNode(g, v, defaultStack, sg);
  _.merge(g.node(v), attrs);
}

function handleEdgeStmt(g, stmt, defaultStack, sg) {
  var attrs = stmt.attrs,
      prev, curr;
  _.each(stmt.elems, function(elem) {
    handleStmt(g, elem, defaultStack, sg);

    switch(elem.type) {
      case "node": curr = [elem.id]; break;
      case "subgraph": curr = collectNodeIds(elem); break;
    }

    _.each(prev, function(v) {
      _.each(curr, function(w) {
        var name;
        if (g.hasEdge(v, w) && g.isMultigraph()) {
          name = _.uniqueId("edge");
        }
        if (!g.hasEdge(v, w, name)) {
          g.setEdge(v, w, _.clone(_.last(defaultStack).edge), name);
        }
        _.merge(g.edge(v, w, name), attrs);
      });
    });

    prev = curr;
  });
}

function handleSubgraphStmt(g, stmt, defaultStack, sg) {
  var id = stmt.id;
  if (id === undefined) {
    id = generateSubgraphId(g);
  }

  defaultStack.push(_.clone(_.last(defaultStack)));

  maybeCreateNode(g, id, defaultStack, sg);

  _.each(stmt.stmts, function(s) {
    handleStmt(g, s, defaultStack, id);
  });

  // If there are no statements remove the subgraph
  if (!g.children(id).length) {
    g.removeNode(id);
  }

  defaultStack.pop();
}

function handleAttrStmt(g, stmt, defaultStack) {
  if (stmt.attrType === "graph") {
    _.merge(g.graph(), stmt.attrs);
  } else {
    _.merge(_.last(defaultStack)[stmt.attrType], stmt.attrs);
  }
}

function handleInlineAttrsStmt(g, stmt, defaultStack, sg) {
  _.merge(sg ? g.node(sg) : g.graph(), stmt.attrs);
}

function generateSubgraphId(g) {
  var id;
  do {
    id = _.uniqueId("sg");
  } while (g.hasNode(id));
  return id;
}

function maybeCreateNode(g, v, defaultStack, sg) {
  if (!g.hasNode(v)) {
    g.setNode(v, _.clone(_.last(defaultStack).node));
    g.setParent(v, sg);
  }
}

// Collect all nodes involved in a subgraph statement
function collectNodeIds(stmt) {
  var ids = {},
      stack = [],
      curr;

  var push = stack.push.bind(stack);

  push(stmt);
  while(stack.length) {
    curr = stack.pop();
    switch(curr.type) {
      case "node": ids[curr.id] = true; break;
      case "edge": _.each(curr.elems, push); break;
      case "subgraph": _.each(curr.stmts, push); break;
    }
  }

  return _.keys(ids);
}


},{"./graphlib":5,"./lodash":6}],4:[function(require,module,exports){
module.exports = (function() {
  /*
   * Generated by PEG.js 0.8.0.
   *
   * http://pegjs.majda.cz/
   */

  function peg$subclass(child, parent) {
    function ctor() { this.constructor = child; }
    ctor.prototype = parent.prototype;
    child.prototype = new ctor();
  }

  function SyntaxError(message, expected, found, offset, line, column) {
    this.message  = message;
    this.expected = expected;
    this.found    = found;
    this.offset   = offset;
    this.line     = line;
    this.column   = column;

    this.name     = "SyntaxError";
  }

  peg$subclass(SyntaxError, Error);

  function parse(input) {
    var options = arguments.length > 1 ? arguments[1] : {},

        peg$FAILED = {},

        peg$startRuleFunctions = { start: peg$parsestart, graphStmt: peg$parsegraphStmt },
        peg$startRuleFunction  = peg$parsestart,

        peg$c0 = [],
        peg$c1 = peg$FAILED,
        peg$c2 = null,
        peg$c3 = "{",
        peg$c4 = { type: "literal", value: "{", description: "\"{\"" },
        peg$c5 = "}",
        peg$c6 = { type: "literal", value: "}", description: "\"}\"" },
        peg$c7 = function(strict, type, id, stmts) {
              return {type: type, id: id, strict: strict !== null, stmts: stmts};
            },
        peg$c8 = ";",
        peg$c9 = { type: "literal", value: ";", description: "\";\"" },
        peg$c10 = function(first, rest) {
              var result = [first];
              for (var i = 0; i < rest.length; ++i) {
                result.push(rest[i][1]);
              }
              return result;
            },
        peg$c11 = function(type, attrs) {
              return { type: "attr", attrType: type, attrs: attrs || {}};
            },
        peg$c12 = "=",
        peg$c13 = { type: "literal", value: "=", description: "\"=\"" },
        peg$c14 = function(k, v) {
              var attrs = {};
              attrs[k] = v;
              return { type: "inlineAttr", attrs: attrs };
            },
        peg$c15 = function(id, attrs) { return {type: "node", id: id, attrs: attrs || {}}; },
        peg$c16 = function(lhs, rhs, attrs) {
              var elems = [lhs];
              for (var i = 0; i < rhs.length; ++i) {
                elems.push(rhs[i]);
              }
              return { type: "edge", elems: elems, attrs: attrs || {} };
            },
        peg$c17 = function(id, stmts) {
              id = (id && id[2]) || [];
              return { type: "subgraph", id: id[0], stmts: stmts };
            },
        peg$c18 = function(first, rest) {
              var result = first;
              for (var i = 0; i < rest.length; ++i) {
                _.merge(result, rest[i][1]);
              }
              return result;
            },
        peg$c19 = "[",
        peg$c20 = { type: "literal", value: "[", description: "\"[\"" },
        peg$c21 = "]",
        peg$c22 = { type: "literal", value: "]", description: "\"]\"" },
        peg$c23 = function(aList) { return aList; },
        peg$c24 = ",",
        peg$c25 = { type: "literal", value: ",", description: "\",\"" },
        peg$c26 = function(first, rest) {
              var result = first;
              for (var i = 0; i < rest.length; ++i) {
                _.merge(result, rest[i][3]);
              }
              return result;
            },
        peg$c27 = "--",
        peg$c28 = { type: "literal", value: "--", description: "\"--\"" },
        peg$c29 = function() { return directed; },
        peg$c30 = void 0,
        peg$c31 = "->",
        peg$c32 = { type: "literal", value: "->", description: "\"->\"" },
        peg$c33 = function(rhs, rest) {
              var result = [rhs];
              if (rest) {
                for (var i = 0; i < rest.length; ++i) {
                  result.push(rest[i]);
                }
              }
              return result;
            },
        peg$c34 = function(k, v) {
              var result = {};
              result[k] = v[3];
              return result;
            },
        peg$c35 = function(id) { return { type: "node", id: id, attrs: {} }; },
        peg$c36 = function(id) { return id; },
        peg$c37 = ":",
        peg$c38 = { type: "literal", value: ":", description: "\":\"" },
        peg$c39 = "ne",
        peg$c40 = { type: "literal", value: "ne", description: "\"ne\"" },
        peg$c41 = "se",
        peg$c42 = { type: "literal", value: "se", description: "\"se\"" },
        peg$c43 = "sw",
        peg$c44 = { type: "literal", value: "sw", description: "\"sw\"" },
        peg$c45 = "nw",
        peg$c46 = { type: "literal", value: "nw", description: "\"nw\"" },
        peg$c47 = "n",
        peg$c48 = { type: "literal", value: "n", description: "\"n\"" },
        peg$c49 = "e",
        peg$c50 = { type: "literal", value: "e", description: "\"e\"" },
        peg$c51 = "s",
        peg$c52 = { type: "literal", value: "s", description: "\"s\"" },
        peg$c53 = "w",
        peg$c54 = { type: "literal", value: "w", description: "\"w\"" },
        peg$c55 = "c",
        peg$c56 = { type: "literal", value: "c", description: "\"c\"" },
        peg$c57 = "_",
        peg$c58 = { type: "literal", value: "_", description: "\"_\"" },
        peg$c59 = { type: "other", description: "identifier" },
        peg$c60 = /^[a-zA-Z\u0200-\u0377_]/,
        peg$c61 = { type: "class", value: "[a-zA-Z\\u0200-\\u0377_]", description: "[a-zA-Z\\u0200-\\u0377_]" },
        peg$c62 = /^[a-zA-Z\u0200-\u0377_0-9]/,
        peg$c63 = { type: "class", value: "[a-zA-Z\\u0200-\\u0377_0-9]", description: "[a-zA-Z\\u0200-\\u0377_0-9]" },
        peg$c64 = function(fst, rest) { return fst + rest.join(""); },
        peg$c65 = "-",
        peg$c66 = { type: "literal", value: "-", description: "\"-\"" },
        peg$c67 = ".",
        peg$c68 = { type: "literal", value: ".", description: "\".\"" },
        peg$c69 = /^[0-9]/,
        peg$c70 = { type: "class", value: "[0-9]", description: "[0-9]" },
        peg$c71 = function(sign, dot, after) {
              return (sign || "") + dot + after.join("");
            },
        peg$c72 = function(sign, before, after) {
              return (sign || "") + before.join("") + (after ? after[0] : "") + (after ? after[1].join("") : "");
            },
        peg$c73 = "\"",
        peg$c74 = { type: "literal", value: "\"", description: "\"\\\"\"" },
        peg$c75 = "\\\"",
        peg$c76 = { type: "literal", value: "\\\"", description: "\"\\\\\\\"\"" },
        peg$c77 = function() { return '"'; },
        peg$c78 = "\\",
        peg$c79 = { type: "literal", value: "\\", description: "\"\\\\\"" },
        peg$c80 = /^[^"]/,
        peg$c81 = { type: "class", value: "[^\"]", description: "[^\"]" },
        peg$c82 = function(ch) { return "\\" + ch; },
        peg$c83 = function(id) {
              return id.join("");
            },
        peg$c84 = "node",
        peg$c85 = { type: "literal", value: "node", description: "\"node\"" },
        peg$c86 = function(k) { return k.toLowerCase(); },
        peg$c87 = "edge",
        peg$c88 = { type: "literal", value: "edge", description: "\"edge\"" },
        peg$c89 = "graph",
        peg$c90 = { type: "literal", value: "graph", description: "\"graph\"" },
        peg$c91 = "digraph",
        peg$c92 = { type: "literal", value: "digraph", description: "\"digraph\"" },
        peg$c93 = "subgraph",
        peg$c94 = { type: "literal", value: "subgraph", description: "\"subgraph\"" },
        peg$c95 = "strict",
        peg$c96 = { type: "literal", value: "strict", description: "\"strict\"" },
        peg$c97 = function(graph) {
              directed = graph === "digraph";
              return graph;
            },
        peg$c98 = { type: "other", description: "whitespace" },
        peg$c99 = /^[ \t\r\n]/,
        peg$c100 = { type: "class", value: "[ \\t\\r\\n]", description: "[ \\t\\r\\n]" },
        peg$c101 = { type: "other", description: "comment" },
        peg$c102 = "//",
        peg$c103 = { type: "literal", value: "//", description: "\"//\"" },
        peg$c104 = /^[^\n]/,
        peg$c105 = { type: "class", value: "[^\\n]", description: "[^\\n]" },
        peg$c106 = "/*",
        peg$c107 = { type: "literal", value: "/*", description: "\"/*\"" },
        peg$c108 = "*/",
        peg$c109 = { type: "literal", value: "*/", description: "\"*/\"" },
        peg$c110 = { type: "any", description: "any character" },

        peg$currPos          = 0,
        peg$reportedPos      = 0,
        peg$cachedPos        = 0,
        peg$cachedPosDetails = { line: 1, column: 1, seenCR: false },
        peg$maxFailPos       = 0,
        peg$maxFailExpected  = [],
        peg$silentFails      = 0,

        peg$result;

    if ("startRule" in options) {
      if (!(options.startRule in peg$startRuleFunctions)) {
        throw new Error("Can't start parsing from rule \"" + options.startRule + "\".");
      }

      peg$startRuleFunction = peg$startRuleFunctions[options.startRule];
    }

    function text() {
      return input.substring(peg$reportedPos, peg$currPos);
    }

    function offset() {
      return peg$reportedPos;
    }

    function line() {
      return peg$computePosDetails(peg$reportedPos).line;
    }

    function column() {
      return peg$computePosDetails(peg$reportedPos).column;
    }

    function expected(description) {
      throw peg$buildException(
        null,
        [{ type: "other", description: description }],
        peg$reportedPos
      );
    }

    function error(message) {
      throw peg$buildException(message, null, peg$reportedPos);
    }

    function peg$computePosDetails(pos) {
      function advance(details, startPos, endPos) {
        var p, ch;

        for (p = startPos; p < endPos; p++) {
          ch = input.charAt(p);
          if (ch === "\n") {
            if (!details.seenCR) { details.line++; }
            details.column = 1;
            details.seenCR = false;
          } else if (ch === "\r" || ch === "\u2028" || ch === "\u2029") {
            details.line++;
            details.column = 1;
            details.seenCR = true;
          } else {
            details.column++;
            details.seenCR = false;
          }
        }
      }

      if (peg$cachedPos !== pos) {
        if (peg$cachedPos > pos) {
          peg$cachedPos = 0;
          peg$cachedPosDetails = { line: 1, column: 1, seenCR: false };
        }
        advance(peg$cachedPosDetails, peg$cachedPos, pos);
        peg$cachedPos = pos;
      }

      return peg$cachedPosDetails;
    }

    function peg$fail(expected) {
      if (peg$currPos < peg$maxFailPos) { return; }

      if (peg$currPos > peg$maxFailPos) {
        peg$maxFailPos = peg$currPos;
        peg$maxFailExpected = [];
      }

      peg$maxFailExpected.push(expected);
    }

    function peg$buildException(message, expected, pos) {
      function cleanupExpected(expected) {
        var i = 1;

        expected.sort(function(a, b) {
          if (a.description < b.description) {
            return -1;
          } else if (a.description > b.description) {
            return 1;
          } else {
            return 0;
          }
        });

        while (i < expected.length) {
          if (expected[i - 1] === expected[i]) {
            expected.splice(i, 1);
          } else {
            i++;
          }
        }
      }

      function buildMessage(expected, found) {
        function stringEscape(s) {
          function hex(ch) { return ch.charCodeAt(0).toString(16).toUpperCase(); }

          return s
            .replace(/\\/g,   '\\\\')
            .replace(/"/g,    '\\"')
            .replace(/\x08/g, '\\b')
            .replace(/\t/g,   '\\t')
            .replace(/\n/g,   '\\n')
            .replace(/\f/g,   '\\f')
            .replace(/\r/g,   '\\r')
            .replace(/[\x00-\x07\x0B\x0E\x0F]/g, function(ch) { return '\\x0' + hex(ch); })
            .replace(/[\x10-\x1F\x80-\xFF]/g,    function(ch) { return '\\x'  + hex(ch); })
            .replace(/[\u0180-\u0FFF]/g,         function(ch) { return '\\u0' + hex(ch); })
            .replace(/[\u1080-\uFFFF]/g,         function(ch) { return '\\u'  + hex(ch); });
        }

        var expectedDescs = new Array(expected.length),
            expectedDesc, foundDesc, i;

        for (i = 0; i < expected.length; i++) {
          expectedDescs[i] = expected[i].description;
        }

        expectedDesc = expected.length > 1
          ? expectedDescs.slice(0, -1).join(", ")
              + " or "
              + expectedDescs[expected.length - 1]
          : expectedDescs[0];

        foundDesc = found ? "\"" + stringEscape(found) + "\"" : "end of input";

        return "Expected " + expectedDesc + " but " + foundDesc + " found.";
      }

      var posDetails = peg$computePosDetails(pos),
          found      = pos < input.length ? input.charAt(pos) : null;

      if (expected !== null) {
        cleanupExpected(expected);
      }

      return new SyntaxError(
        message !== null ? message : buildMessage(expected, found),
        expected,
        found,
        pos,
        posDetails.line,
        posDetails.column
      );
    }

    function peg$parsestart() {
      var s0, s1;

      s0 = [];
      s1 = peg$parsegraphStmt();
      if (s1 !== peg$FAILED) {
        while (s1 !== peg$FAILED) {
          s0.push(s1);
          s1 = peg$parsegraphStmt();
        }
      } else {
        s0 = peg$c1;
      }

      return s0;
    }

    function peg$parsegraphStmt() {
      var s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13;

      s0 = peg$currPos;
      s1 = [];
      s2 = peg$parse_();
      while (s2 !== peg$FAILED) {
        s1.push(s2);
        s2 = peg$parse_();
      }
      if (s1 !== peg$FAILED) {
        s2 = peg$currPos;
        s3 = peg$parsestrict();
        if (s3 !== peg$FAILED) {
          s4 = peg$parse_();
          if (s4 !== peg$FAILED) {
            s3 = [s3, s4];
            s2 = s3;
          } else {
            peg$currPos = s2;
            s2 = peg$c1;
          }
        } else {
          peg$currPos = s2;
          s2 = peg$c1;
        }
        if (s2 === peg$FAILED) {
          s2 = peg$c2;
        }
        if (s2 !== peg$FAILED) {
          s3 = peg$parsegraphType();
          if (s3 !== peg$FAILED) {
            s4 = [];
            s5 = peg$parse_();
            while (s5 !== peg$FAILED) {
              s4.push(s5);
              s5 = peg$parse_();
            }
            if (s4 !== peg$FAILED) {
              s5 = peg$parseid();
              if (s5 === peg$FAILED) {
                s5 = peg$c2;
              }
              if (s5 !== peg$FAILED) {
                s6 = [];
                s7 = peg$parse_();
                while (s7 !== peg$FAILED) {
                  s6.push(s7);
                  s7 = peg$parse_();
                }
                if (s6 !== peg$FAILED) {
                  if (input.charCodeAt(peg$currPos) === 123) {
                    s7 = peg$c3;
                    peg$currPos++;
                  } else {
                    s7 = peg$FAILED;
                    if (peg$silentFails === 0) { peg$fail(peg$c4); }
                  }
                  if (s7 !== peg$FAILED) {
                    s8 = [];
                    s9 = peg$parse_();
                    while (s9 !== peg$FAILED) {
                      s8.push(s9);
                      s9 = peg$parse_();
                    }
                    if (s8 !== peg$FAILED) {
                      s9 = peg$parsestmtList();
                      if (s9 === peg$FAILED) {
                        s9 = peg$c2;
                      }
                      if (s9 !== peg$FAILED) {
                        s10 = [];
                        s11 = peg$parse_();
                        while (s11 !== peg$FAILED) {
                          s10.push(s11);
                          s11 = peg$parse_();
                        }
                        if (s10 !== peg$FAILED) {
                          if (input.charCodeAt(peg$currPos) === 125) {
                            s11 = peg$c5;
                            peg$currPos++;
                          } else {
                            s11 = peg$FAILED;
                            if (peg$silentFails === 0) { peg$fail(peg$c6); }
                          }
                          if (s11 !== peg$FAILED) {
                            s12 = [];
                            s13 = peg$parse_();
                            while (s13 !== peg$FAILED) {
                              s12.push(s13);
                              s13 = peg$parse_();
                            }
                            if (s12 !== peg$FAILED) {
                              peg$reportedPos = s0;
                              s1 = peg$c7(s2, s3, s5, s9);
                              s0 = s1;
                            } else {
                              peg$currPos = s0;
                              s0 = peg$c1;
                            }
                          } else {
                            peg$currPos = s0;
                            s0 = peg$c1;
                          }
                        } else {
                          peg$currPos = s0;
                          s0 = peg$c1;
                        }
                      } else {
                        peg$currPos = s0;
                        s0 = peg$c1;
                      }
                    } else {
                      peg$currPos = s0;
                      s0 = peg$c1;
                    }
                  } else {
                    peg$currPos = s0;
                    s0 = peg$c1;
                  }
                } else {
                  peg$currPos = s0;
                  s0 = peg$c1;
                }
              } else {
                peg$currPos = s0;
                s0 = peg$c1;
              }
            } else {
              peg$currPos = s0;
              s0 = peg$c1;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$c1;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$c1;
      }

      return s0;
    }

    function peg$parsestmtList() {
      var s0, s1, s2, s3, s4, s5, s6, s7, s8, s9;

      s0 = peg$currPos;
      s1 = peg$parsestmt();
      if (s1 !== peg$FAILED) {
        s2 = [];
        s3 = peg$parse_();
        while (s3 !== peg$FAILED) {
          s2.push(s3);
          s3 = peg$parse_();
        }
        if (s2 !== peg$FAILED) {
          if (input.charCodeAt(peg$currPos) === 59) {
            s3 = peg$c8;
            peg$currPos++;
          } else {
            s3 = peg$FAILED;
            if (peg$silentFails === 0) { peg$fail(peg$c9); }
          }
          if (s3 === peg$FAILED) {
            s3 = peg$c2;
          }
          if (s3 !== peg$FAILED) {
            s4 = [];
            s5 = peg$currPos;
            s6 = [];
            s7 = peg$parse_();
            while (s7 !== peg$FAILED) {
              s6.push(s7);
              s7 = peg$parse_();
            }
            if (s6 !== peg$FAILED) {
              s7 = peg$parsestmt();
              if (s7 !== peg$FAILED) {
                s8 = [];
                s9 = peg$parse_();
                while (s9 !== peg$FAILED) {
                  s8.push(s9);
                  s9 = peg$parse_();
                }
                if (s8 !== peg$FAILED) {
                  if (input.charCodeAt(peg$currPos) === 59) {
                    s9 = peg$c8;
                    peg$currPos++;
                  } else {
                    s9 = peg$FAILED;
                    if (peg$silentFails === 0) { peg$fail(peg$c9); }
                  }
                  if (s9 === peg$FAILED) {
                    s9 = peg$c2;
                  }
                  if (s9 !== peg$FAILED) {
                    s6 = [s6, s7, s8, s9];
                    s5 = s6;
                  } else {
                    peg$currPos = s5;
                    s5 = peg$c1;
                  }
                } else {
                  peg$currPos = s5;
                  s5 = peg$c1;
                }
              } else {
                peg$currPos = s5;
                s5 = peg$c1;
              }
            } else {
              peg$currPos = s5;
              s5 = peg$c1;
            }
            while (s5 !== peg$FAILED) {
              s4.push(s5);
              s5 = peg$currPos;
              s6 = [];
              s7 = peg$parse_();
              while (s7 !== peg$FAILED) {
                s6.push(s7);
                s7 = peg$parse_();
              }
              if (s6 !== peg$FAILED) {
                s7 = peg$parsestmt();
                if (s7 !== peg$FAILED) {
                  s8 = [];
                  s9 = peg$parse_();
                  while (s9 !== peg$FAILED) {
                    s8.push(s9);
                    s9 = peg$parse_();
                  }
                  if (s8 !== peg$FAILED) {
                    if (input.charCodeAt(peg$currPos) === 59) {
                      s9 = peg$c8;
                      peg$currPos++;
                    } else {
                      s9 = peg$FAILED;
                      if (peg$silentFails === 0) { peg$fail(peg$c9); }
                    }
                    if (s9 === peg$FAILED) {
                      s9 = peg$c2;
                    }
                    if (s9 !== peg$FAILED) {
                      s6 = [s6, s7, s8, s9];
                      s5 = s6;
                    } else {
                      peg$currPos = s5;
                      s5 = peg$c1;
                    }
                  } else {
                    peg$currPos = s5;
                    s5 = peg$c1;
                  }
                } else {
                  peg$currPos = s5;
                  s5 = peg$c1;
                }
              } else {
                peg$currPos = s5;
                s5 = peg$c1;
              }
            }
            if (s4 !== peg$FAILED) {
              peg$reportedPos = s0;
              s1 = peg$c10(s1, s4);
              s0 = s1;
            } else {
              peg$currPos = s0;
              s0 = peg$c1;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$c1;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$c1;
      }

      return s0;
    }

    function peg$parsestmt() {
      var s0;

      s0 = peg$parseattrStmt();
      if (s0 === peg$FAILED) {
        s0 = peg$parseedgeStmt();
        if (s0 === peg$FAILED) {
          s0 = peg$parsesubgraphStmt();
          if (s0 === peg$FAILED) {
            s0 = peg$parseinlineAttrStmt();
            if (s0 === peg$FAILED) {
              s0 = peg$parsenodeStmt();
            }
          }
        }
      }

      return s0;
    }

    function peg$parseattrStmt() {
      var s0, s1, s2, s3;

      s0 = peg$currPos;
      s1 = peg$parsegraph();
      if (s1 === peg$FAILED) {
        s1 = peg$parsenode();
        if (s1 === peg$FAILED) {
          s1 = peg$parseedge();
        }
      }
      if (s1 !== peg$FAILED) {
        s2 = [];
        s3 = peg$parse_();
        while (s3 !== peg$FAILED) {
          s2.push(s3);
          s3 = peg$parse_();
        }
        if (s2 !== peg$FAILED) {
          s3 = peg$parseattrList();
          if (s3 !== peg$FAILED) {
            peg$reportedPos = s0;
            s1 = peg$c11(s1, s3);
            s0 = s1;
          } else {
            peg$currPos = s0;
            s0 = peg$c1;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$c1;
      }

      return s0;
    }

    function peg$parseinlineAttrStmt() {
      var s0, s1, s2, s3, s4, s5;

      s0 = peg$currPos;
      s1 = peg$parseid();
      if (s1 !== peg$FAILED) {
        s2 = [];
        s3 = peg$parse_();
        while (s3 !== peg$FAILED) {
          s2.push(s3);
          s3 = peg$parse_();
        }
        if (s2 !== peg$FAILED) {
          if (input.charCodeAt(peg$currPos) === 61) {
            s3 = peg$c12;
            peg$currPos++;
          } else {
            s3 = peg$FAILED;
            if (peg$silentFails === 0) { peg$fail(peg$c13); }
          }
          if (s3 !== peg$FAILED) {
            s4 = [];
            s5 = peg$parse_();
            while (s5 !== peg$FAILED) {
              s4.push(s5);
              s5 = peg$parse_();
            }
            if (s4 !== peg$FAILED) {
              s5 = peg$parseid();
              if (s5 !== peg$FAILED) {
                peg$reportedPos = s0;
                s1 = peg$c14(s1, s5);
                s0 = s1;
              } else {
                peg$currPos = s0;
                s0 = peg$c1;
              }
            } else {
              peg$currPos = s0;
              s0 = peg$c1;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$c1;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$c1;
      }

      return s0;
    }

    function peg$parsenodeStmt() {
      var s0, s1, s2, s3;

      s0 = peg$currPos;
      s1 = peg$parsenodeId();
      if (s1 !== peg$FAILED) {
        s2 = [];
        s3 = peg$parse_();
        while (s3 !== peg$FAILED) {
          s2.push(s3);
          s3 = peg$parse_();
        }
        if (s2 !== peg$FAILED) {
          s3 = peg$parseattrList();
          if (s3 === peg$FAILED) {
            s3 = peg$c2;
          }
          if (s3 !== peg$FAILED) {
            peg$reportedPos = s0;
            s1 = peg$c15(s1, s3);
            s0 = s1;
          } else {
            peg$currPos = s0;
            s0 = peg$c1;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$c1;
      }

      return s0;
    }

    function peg$parseedgeStmt() {
      var s0, s1, s2, s3, s4, s5;

      s0 = peg$currPos;
      s1 = peg$parsenodeIdOrSubgraph();
      if (s1 !== peg$FAILED) {
        s2 = [];
        s3 = peg$parse_();
        while (s3 !== peg$FAILED) {
          s2.push(s3);
          s3 = peg$parse_();
        }
        if (s2 !== peg$FAILED) {
          s3 = peg$parseedgeRHS();
          if (s3 !== peg$FAILED) {
            s4 = [];
            s5 = peg$parse_();
            while (s5 !== peg$FAILED) {
              s4.push(s5);
              s5 = peg$parse_();
            }
            if (s4 !== peg$FAILED) {
              s5 = peg$parseattrList();
              if (s5 === peg$FAILED) {
                s5 = peg$c2;
              }
              if (s5 !== peg$FAILED) {
                peg$reportedPos = s0;
                s1 = peg$c16(s1, s3, s5);
                s0 = s1;
              } else {
                peg$currPos = s0;
                s0 = peg$c1;
              }
            } else {
              peg$currPos = s0;
              s0 = peg$c1;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$c1;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$c1;
      }

      return s0;
    }

    function peg$parsesubgraphStmt() {
      var s0, s1, s2, s3, s4, s5, s6, s7;

      s0 = peg$currPos;
      s1 = peg$currPos;
      s2 = peg$parsesubgraph();
      if (s2 !== peg$FAILED) {
        s3 = [];
        s4 = peg$parse_();
        while (s4 !== peg$FAILED) {
          s3.push(s4);
          s4 = peg$parse_();
        }
        if (s3 !== peg$FAILED) {
          s4 = peg$currPos;
          s5 = peg$parseid();
          if (s5 !== peg$FAILED) {
            s6 = [];
            s7 = peg$parse_();
            while (s7 !== peg$FAILED) {
              s6.push(s7);
              s7 = peg$parse_();
            }
            if (s6 !== peg$FAILED) {
              s5 = [s5, s6];
              s4 = s5;
            } else {
              peg$currPos = s4;
              s4 = peg$c1;
            }
          } else {
            peg$currPos = s4;
            s4 = peg$c1;
          }
          if (s4 === peg$FAILED) {
            s4 = peg$c2;
          }
          if (s4 !== peg$FAILED) {
            s2 = [s2, s3, s4];
            s1 = s2;
          } else {
            peg$currPos = s1;
            s1 = peg$c1;
          }
        } else {
          peg$currPos = s1;
          s1 = peg$c1;
        }
      } else {
        peg$currPos = s1;
        s1 = peg$c1;
      }
      if (s1 === peg$FAILED) {
        s1 = peg$c2;
      }
      if (s1 !== peg$FAILED) {
        if (input.charCodeAt(peg$currPos) === 123) {
          s2 = peg$c3;
          peg$currPos++;
        } else {
          s2 = peg$FAILED;
          if (peg$silentFails === 0) { peg$fail(peg$c4); }
        }
        if (s2 !== peg$FAILED) {
          s3 = [];
          s4 = peg$parse_();
          while (s4 !== peg$FAILED) {
            s3.push(s4);
            s4 = peg$parse_();
          }
          if (s3 !== peg$FAILED) {
            s4 = peg$parsestmtList();
            if (s4 === peg$FAILED) {
              s4 = peg$c2;
            }
            if (s4 !== peg$FAILED) {
              s5 = [];
              s6 = peg$parse_();
              while (s6 !== peg$FAILED) {
                s5.push(s6);
                s6 = peg$parse_();
              }
              if (s5 !== peg$FAILED) {
                if (input.charCodeAt(peg$currPos) === 125) {
                  s6 = peg$c5;
                  peg$currPos++;
                } else {
                  s6 = peg$FAILED;
                  if (peg$silentFails === 0) { peg$fail(peg$c6); }
                }
                if (s6 !== peg$FAILED) {
                  peg$reportedPos = s0;
                  s1 = peg$c17(s1, s4);
                  s0 = s1;
                } else {
                  peg$currPos = s0;
                  s0 = peg$c1;
                }
              } else {
                peg$currPos = s0;
                s0 = peg$c1;
              }
            } else {
              peg$currPos = s0;
              s0 = peg$c1;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$c1;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$c1;
      }

      return s0;
    }

    function peg$parseattrList() {
      var s0, s1, s2, s3, s4, s5;

      s0 = peg$currPos;
      s1 = peg$parseattrListBlock();
      if (s1 !== peg$FAILED) {
        s2 = [];
        s3 = peg$currPos;
        s4 = [];
        s5 = peg$parse_();
        while (s5 !== peg$FAILED) {
          s4.push(s5);
          s5 = peg$parse_();
        }
        if (s4 !== peg$FAILED) {
          s5 = peg$parseattrListBlock();
          if (s5 !== peg$FAILED) {
            s4 = [s4, s5];
            s3 = s4;
          } else {
            peg$currPos = s3;
            s3 = peg$c1;
          }
        } else {
          peg$currPos = s3;
          s3 = peg$c1;
        }
        while (s3 !== peg$FAILED) {
          s2.push(s3);
          s3 = peg$currPos;
          s4 = [];
          s5 = peg$parse_();
          while (s5 !== peg$FAILED) {
            s4.push(s5);
            s5 = peg$parse_();
          }
          if (s4 !== peg$FAILED) {
            s5 = peg$parseattrListBlock();
            if (s5 !== peg$FAILED) {
              s4 = [s4, s5];
              s3 = s4;
            } else {
              peg$currPos = s3;
              s3 = peg$c1;
            }
          } else {
            peg$currPos = s3;
            s3 = peg$c1;
          }
        }
        if (s2 !== peg$FAILED) {
          peg$reportedPos = s0;
          s1 = peg$c18(s1, s2);
          s0 = s1;
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$c1;
      }

      return s0;
    }

    function peg$parseattrListBlock() {
      var s0, s1, s2, s3, s4, s5;

      s0 = peg$currPos;
      if (input.charCodeAt(peg$currPos) === 91) {
        s1 = peg$c19;
        peg$currPos++;
      } else {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) { peg$fail(peg$c20); }
      }
      if (s1 !== peg$FAILED) {
        s2 = [];
        s3 = peg$parse_();
        while (s3 !== peg$FAILED) {
          s2.push(s3);
          s3 = peg$parse_();
        }
        if (s2 !== peg$FAILED) {
          s3 = peg$parseaList();
          if (s3 === peg$FAILED) {
            s3 = peg$c2;
          }
          if (s3 !== peg$FAILED) {
            s4 = [];
            s5 = peg$parse_();
            while (s5 !== peg$FAILED) {
              s4.push(s5);
              s5 = peg$parse_();
            }
            if (s4 !== peg$FAILED) {
              if (input.charCodeAt(peg$currPos) === 93) {
                s5 = peg$c21;
                peg$currPos++;
              } else {
                s5 = peg$FAILED;
                if (peg$silentFails === 0) { peg$fail(peg$c22); }
              }
              if (s5 !== peg$FAILED) {
                peg$reportedPos = s0;
                s1 = peg$c23(s3);
                s0 = s1;
              } else {
                peg$currPos = s0;
                s0 = peg$c1;
              }
            } else {
              peg$currPos = s0;
              s0 = peg$c1;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$c1;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$c1;
      }

      return s0;
    }

    function peg$parseaList() {
      var s0, s1, s2, s3, s4, s5, s6, s7;

      s0 = peg$currPos;
      s1 = peg$parseidDef();
      if (s1 !== peg$FAILED) {
        s2 = [];
        s3 = peg$currPos;
        s4 = [];
        s5 = peg$parse_();
        while (s5 !== peg$FAILED) {
          s4.push(s5);
          s5 = peg$parse_();
        }
        if (s4 !== peg$FAILED) {
          if (input.charCodeAt(peg$currPos) === 44) {
            s5 = peg$c24;
            peg$currPos++;
          } else {
            s5 = peg$FAILED;
            if (peg$silentFails === 0) { peg$fail(peg$c25); }
          }
          if (s5 === peg$FAILED) {
            s5 = peg$c2;
          }
          if (s5 !== peg$FAILED) {
            s6 = [];
            s7 = peg$parse_();
            while (s7 !== peg$FAILED) {
              s6.push(s7);
              s7 = peg$parse_();
            }
            if (s6 !== peg$FAILED) {
              s7 = peg$parseidDef();
              if (s7 !== peg$FAILED) {
                s4 = [s4, s5, s6, s7];
                s3 = s4;
              } else {
                peg$currPos = s3;
                s3 = peg$c1;
              }
            } else {
              peg$currPos = s3;
              s3 = peg$c1;
            }
          } else {
            peg$currPos = s3;
            s3 = peg$c1;
          }
        } else {
          peg$currPos = s3;
          s3 = peg$c1;
        }
        while (s3 !== peg$FAILED) {
          s2.push(s3);
          s3 = peg$currPos;
          s4 = [];
          s5 = peg$parse_();
          while (s5 !== peg$FAILED) {
            s4.push(s5);
            s5 = peg$parse_();
          }
          if (s4 !== peg$FAILED) {
            if (input.charCodeAt(peg$currPos) === 44) {
              s5 = peg$c24;
              peg$currPos++;
            } else {
              s5 = peg$FAILED;
              if (peg$silentFails === 0) { peg$fail(peg$c25); }
            }
            if (s5 === peg$FAILED) {
              s5 = peg$c2;
            }
            if (s5 !== peg$FAILED) {
              s6 = [];
              s7 = peg$parse_();
              while (s7 !== peg$FAILED) {
                s6.push(s7);
                s7 = peg$parse_();
              }
              if (s6 !== peg$FAILED) {
                s7 = peg$parseidDef();
                if (s7 !== peg$FAILED) {
                  s4 = [s4, s5, s6, s7];
                  s3 = s4;
                } else {
                  peg$currPos = s3;
                  s3 = peg$c1;
                }
              } else {
                peg$currPos = s3;
                s3 = peg$c1;
              }
            } else {
              peg$currPos = s3;
              s3 = peg$c1;
            }
          } else {
            peg$currPos = s3;
            s3 = peg$c1;
          }
        }
        if (s2 !== peg$FAILED) {
          peg$reportedPos = s0;
          s1 = peg$c26(s1, s2);
          s0 = s1;
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$c1;
      }

      return s0;
    }

    function peg$parseedgeRHS() {
      var s0, s1, s2, s3, s4, s5;

      s0 = peg$currPos;
      s1 = peg$currPos;
      if (input.substr(peg$currPos, 2) === peg$c27) {
        s2 = peg$c27;
        peg$currPos += 2;
      } else {
        s2 = peg$FAILED;
        if (peg$silentFails === 0) { peg$fail(peg$c28); }
      }
      if (s2 !== peg$FAILED) {
        peg$reportedPos = peg$currPos;
        s3 = peg$c29();
        if (s3) {
          s3 = peg$c1;
        } else {
          s3 = peg$c30;
        }
        if (s3 !== peg$FAILED) {
          s2 = [s2, s3];
          s1 = s2;
        } else {
          peg$currPos = s1;
          s1 = peg$c1;
        }
      } else {
        peg$currPos = s1;
        s1 = peg$c1;
      }
      if (s1 === peg$FAILED) {
        s1 = peg$currPos;
        if (input.substr(peg$currPos, 2) === peg$c31) {
          s2 = peg$c31;
          peg$currPos += 2;
        } else {
          s2 = peg$FAILED;
          if (peg$silentFails === 0) { peg$fail(peg$c32); }
        }
        if (s2 !== peg$FAILED) {
          peg$reportedPos = peg$currPos;
          s3 = peg$c29();
          if (s3) {
            s3 = peg$c30;
          } else {
            s3 = peg$c1;
          }
          if (s3 !== peg$FAILED) {
            s2 = [s2, s3];
            s1 = s2;
          } else {
            peg$currPos = s1;
            s1 = peg$c1;
          }
        } else {
          peg$currPos = s1;
          s1 = peg$c1;
        }
      }
      if (s1 !== peg$FAILED) {
        s2 = [];
        s3 = peg$parse_();
        while (s3 !== peg$FAILED) {
          s2.push(s3);
          s3 = peg$parse_();
        }
        if (s2 !== peg$FAILED) {
          s3 = peg$parsenodeIdOrSubgraph();
          if (s3 !== peg$FAILED) {
            s4 = [];
            s5 = peg$parse_();
            while (s5 !== peg$FAILED) {
              s4.push(s5);
              s5 = peg$parse_();
            }
            if (s4 !== peg$FAILED) {
              s5 = peg$parseedgeRHS();
              if (s5 === peg$FAILED) {
                s5 = peg$c2;
              }
              if (s5 !== peg$FAILED) {
                peg$reportedPos = s0;
                s1 = peg$c33(s3, s5);
                s0 = s1;
              } else {
                peg$currPos = s0;
                s0 = peg$c1;
              }
            } else {
              peg$currPos = s0;
              s0 = peg$c1;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$c1;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$c1;
      }

      return s0;
    }

    function peg$parseidDef() {
      var s0, s1, s2, s3, s4, s5, s6;

      s0 = peg$currPos;
      s1 = peg$parseid();
      if (s1 !== peg$FAILED) {
        s2 = peg$currPos;
        s3 = [];
        s4 = peg$parse_();
        while (s4 !== peg$FAILED) {
          s3.push(s4);
          s4 = peg$parse_();
        }
        if (s3 !== peg$FAILED) {
          if (input.charCodeAt(peg$currPos) === 61) {
            s4 = peg$c12;
            peg$currPos++;
          } else {
            s4 = peg$FAILED;
            if (peg$silentFails === 0) { peg$fail(peg$c13); }
          }
          if (s4 !== peg$FAILED) {
            s5 = [];
            s6 = peg$parse_();
            while (s6 !== peg$FAILED) {
              s5.push(s6);
              s6 = peg$parse_();
            }
            if (s5 !== peg$FAILED) {
              s6 = peg$parseid();
              if (s6 !== peg$FAILED) {
                s3 = [s3, s4, s5, s6];
                s2 = s3;
              } else {
                peg$currPos = s2;
                s2 = peg$c1;
              }
            } else {
              peg$currPos = s2;
              s2 = peg$c1;
            }
          } else {
            peg$currPos = s2;
            s2 = peg$c1;
          }
        } else {
          peg$currPos = s2;
          s2 = peg$c1;
        }
        if (s2 === peg$FAILED) {
          s2 = peg$c2;
        }
        if (s2 !== peg$FAILED) {
          peg$reportedPos = s0;
          s1 = peg$c34(s1, s2);
          s0 = s1;
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$c1;
      }

      return s0;
    }

    function peg$parsenodeIdOrSubgraph() {
      var s0, s1;

      s0 = peg$parsesubgraphStmt();
      if (s0 === peg$FAILED) {
        s0 = peg$currPos;
        s1 = peg$parsenodeId();
        if (s1 !== peg$FAILED) {
          peg$reportedPos = s0;
          s1 = peg$c35(s1);
        }
        s0 = s1;
      }

      return s0;
    }

    function peg$parsenodeId() {
      var s0, s1, s2, s3;

      s0 = peg$currPos;
      s1 = peg$parseid();
      if (s1 !== peg$FAILED) {
        s2 = [];
        s3 = peg$parse_();
        while (s3 !== peg$FAILED) {
          s2.push(s3);
          s3 = peg$parse_();
        }
        if (s2 !== peg$FAILED) {
          s3 = peg$parseport();
          if (s3 === peg$FAILED) {
            s3 = peg$c2;
          }
          if (s3 !== peg$FAILED) {
            peg$reportedPos = s0;
            s1 = peg$c36(s1);
            s0 = s1;
          } else {
            peg$currPos = s0;
            s0 = peg$c1;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$c1;
      }

      return s0;
    }

    function peg$parseport() {
      var s0, s1, s2, s3, s4, s5, s6, s7, s8;

      s0 = peg$currPos;
      if (input.charCodeAt(peg$currPos) === 58) {
        s1 = peg$c37;
        peg$currPos++;
      } else {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) { peg$fail(peg$c38); }
      }
      if (s1 !== peg$FAILED) {
        s2 = [];
        s3 = peg$parse_();
        while (s3 !== peg$FAILED) {
          s2.push(s3);
          s3 = peg$parse_();
        }
        if (s2 !== peg$FAILED) {
          s3 = peg$parseid();
          if (s3 !== peg$FAILED) {
            s4 = [];
            s5 = peg$parse_();
            while (s5 !== peg$FAILED) {
              s4.push(s5);
              s5 = peg$parse_();
            }
            if (s4 !== peg$FAILED) {
              s5 = peg$currPos;
              if (input.charCodeAt(peg$currPos) === 58) {
                s6 = peg$c37;
                peg$currPos++;
              } else {
                s6 = peg$FAILED;
                if (peg$silentFails === 0) { peg$fail(peg$c38); }
              }
              if (s6 !== peg$FAILED) {
                s7 = [];
                s8 = peg$parse_();
                while (s8 !== peg$FAILED) {
                  s7.push(s8);
                  s8 = peg$parse_();
                }
                if (s7 !== peg$FAILED) {
                  s8 = peg$parsecompassPt();
                  if (s8 !== peg$FAILED) {
                    s6 = [s6, s7, s8];
                    s5 = s6;
                  } else {
                    peg$currPos = s5;
                    s5 = peg$c1;
                  }
                } else {
                  peg$currPos = s5;
                  s5 = peg$c1;
                }
              } else {
                peg$currPos = s5;
                s5 = peg$c1;
              }
              if (s5 === peg$FAILED) {
                s5 = peg$c2;
              }
              if (s5 !== peg$FAILED) {
                s1 = [s1, s2, s3, s4, s5];
                s0 = s1;
              } else {
                peg$currPos = s0;
                s0 = peg$c1;
              }
            } else {
              peg$currPos = s0;
              s0 = peg$c1;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$c1;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$c1;
      }

      return s0;
    }

    function peg$parsecompassPt() {
      var s0;

      if (input.substr(peg$currPos, 2) === peg$c39) {
        s0 = peg$c39;
        peg$currPos += 2;
      } else {
        s0 = peg$FAILED;
        if (peg$silentFails === 0) { peg$fail(peg$c40); }
      }
      if (s0 === peg$FAILED) {
        if (input.substr(peg$currPos, 2) === peg$c41) {
          s0 = peg$c41;
          peg$currPos += 2;
        } else {
          s0 = peg$FAILED;
          if (peg$silentFails === 0) { peg$fail(peg$c42); }
        }
        if (s0 === peg$FAILED) {
          if (input.substr(peg$currPos, 2) === peg$c43) {
            s0 = peg$c43;
            peg$currPos += 2;
          } else {
            s0 = peg$FAILED;
            if (peg$silentFails === 0) { peg$fail(peg$c44); }
          }
          if (s0 === peg$FAILED) {
            if (input.substr(peg$currPos, 2) === peg$c45) {
              s0 = peg$c45;
              peg$currPos += 2;
            } else {
              s0 = peg$FAILED;
              if (peg$silentFails === 0) { peg$fail(peg$c46); }
            }
            if (s0 === peg$FAILED) {
              if (input.charCodeAt(peg$currPos) === 110) {
                s0 = peg$c47;
                peg$currPos++;
              } else {
                s0 = peg$FAILED;
                if (peg$silentFails === 0) { peg$fail(peg$c48); }
              }
              if (s0 === peg$FAILED) {
                if (input.charCodeAt(peg$currPos) === 101) {
                  s0 = peg$c49;
                  peg$currPos++;
                } else {
                  s0 = peg$FAILED;
                  if (peg$silentFails === 0) { peg$fail(peg$c50); }
                }
                if (s0 === peg$FAILED) {
                  if (input.charCodeAt(peg$currPos) === 115) {
                    s0 = peg$c51;
                    peg$currPos++;
                  } else {
                    s0 = peg$FAILED;
                    if (peg$silentFails === 0) { peg$fail(peg$c52); }
                  }
                  if (s0 === peg$FAILED) {
                    if (input.charCodeAt(peg$currPos) === 119) {
                      s0 = peg$c53;
                      peg$currPos++;
                    } else {
                      s0 = peg$FAILED;
                      if (peg$silentFails === 0) { peg$fail(peg$c54); }
                    }
                    if (s0 === peg$FAILED) {
                      if (input.charCodeAt(peg$currPos) === 99) {
                        s0 = peg$c55;
                        peg$currPos++;
                      } else {
                        s0 = peg$FAILED;
                        if (peg$silentFails === 0) { peg$fail(peg$c56); }
                      }
                      if (s0 === peg$FAILED) {
                        if (input.charCodeAt(peg$currPos) === 95) {
                          s0 = peg$c57;
                          peg$currPos++;
                        } else {
                          s0 = peg$FAILED;
                          if (peg$silentFails === 0) { peg$fail(peg$c58); }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      return s0;
    }

    function peg$parseid() {
      var s0, s1, s2, s3, s4, s5, s6;

      peg$silentFails++;
      s0 = peg$currPos;
      if (peg$c60.test(input.charAt(peg$currPos))) {
        s1 = input.charAt(peg$currPos);
        peg$currPos++;
      } else {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) { peg$fail(peg$c61); }
      }
      if (s1 !== peg$FAILED) {
        s2 = [];
        if (peg$c62.test(input.charAt(peg$currPos))) {
          s3 = input.charAt(peg$currPos);
          peg$currPos++;
        } else {
          s3 = peg$FAILED;
          if (peg$silentFails === 0) { peg$fail(peg$c63); }
        }
        while (s3 !== peg$FAILED) {
          s2.push(s3);
          if (peg$c62.test(input.charAt(peg$currPos))) {
            s3 = input.charAt(peg$currPos);
            peg$currPos++;
          } else {
            s3 = peg$FAILED;
            if (peg$silentFails === 0) { peg$fail(peg$c63); }
          }
        }
        if (s2 !== peg$FAILED) {
          peg$reportedPos = s0;
          s1 = peg$c64(s1, s2);
          s0 = s1;
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$c1;
      }
      if (s0 === peg$FAILED) {
        s0 = peg$currPos;
        if (input.charCodeAt(peg$currPos) === 45) {
          s1 = peg$c65;
          peg$currPos++;
        } else {
          s1 = peg$FAILED;
          if (peg$silentFails === 0) { peg$fail(peg$c66); }
        }
        if (s1 === peg$FAILED) {
          s1 = peg$c2;
        }
        if (s1 !== peg$FAILED) {
          if (input.charCodeAt(peg$currPos) === 46) {
            s2 = peg$c67;
            peg$currPos++;
          } else {
            s2 = peg$FAILED;
            if (peg$silentFails === 0) { peg$fail(peg$c68); }
          }
          if (s2 !== peg$FAILED) {
            s3 = [];
            if (peg$c69.test(input.charAt(peg$currPos))) {
              s4 = input.charAt(peg$currPos);
              peg$currPos++;
            } else {
              s4 = peg$FAILED;
              if (peg$silentFails === 0) { peg$fail(peg$c70); }
            }
            if (s4 !== peg$FAILED) {
              while (s4 !== peg$FAILED) {
                s3.push(s4);
                if (peg$c69.test(input.charAt(peg$currPos))) {
                  s4 = input.charAt(peg$currPos);
                  peg$currPos++;
                } else {
                  s4 = peg$FAILED;
                  if (peg$silentFails === 0) { peg$fail(peg$c70); }
                }
              }
            } else {
              s3 = peg$c1;
            }
            if (s3 !== peg$FAILED) {
              peg$reportedPos = s0;
              s1 = peg$c71(s1, s2, s3);
              s0 = s1;
            } else {
              peg$currPos = s0;
              s0 = peg$c1;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$c1;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
        if (s0 === peg$FAILED) {
          s0 = peg$currPos;
          if (input.charCodeAt(peg$currPos) === 45) {
            s1 = peg$c65;
            peg$currPos++;
          } else {
            s1 = peg$FAILED;
            if (peg$silentFails === 0) { peg$fail(peg$c66); }
          }
          if (s1 === peg$FAILED) {
            s1 = peg$c2;
          }
          if (s1 !== peg$FAILED) {
            s2 = [];
            if (peg$c69.test(input.charAt(peg$currPos))) {
              s3 = input.charAt(peg$currPos);
              peg$currPos++;
            } else {
              s3 = peg$FAILED;
              if (peg$silentFails === 0) { peg$fail(peg$c70); }
            }
            if (s3 !== peg$FAILED) {
              while (s3 !== peg$FAILED) {
                s2.push(s3);
                if (peg$c69.test(input.charAt(peg$currPos))) {
                  s3 = input.charAt(peg$currPos);
                  peg$currPos++;
                } else {
                  s3 = peg$FAILED;
                  if (peg$silentFails === 0) { peg$fail(peg$c70); }
                }
              }
            } else {
              s2 = peg$c1;
            }
            if (s2 !== peg$FAILED) {
              s3 = peg$currPos;
              if (input.charCodeAt(peg$currPos) === 46) {
                s4 = peg$c67;
                peg$currPos++;
              } else {
                s4 = peg$FAILED;
                if (peg$silentFails === 0) { peg$fail(peg$c68); }
              }
              if (s4 !== peg$FAILED) {
                s5 = [];
                if (peg$c69.test(input.charAt(peg$currPos))) {
                  s6 = input.charAt(peg$currPos);
                  peg$currPos++;
                } else {
                  s6 = peg$FAILED;
                  if (peg$silentFails === 0) { peg$fail(peg$c70); }
                }
                while (s6 !== peg$FAILED) {
                  s5.push(s6);
                  if (peg$c69.test(input.charAt(peg$currPos))) {
                    s6 = input.charAt(peg$currPos);
                    peg$currPos++;
                  } else {
                    s6 = peg$FAILED;
                    if (peg$silentFails === 0) { peg$fail(peg$c70); }
                  }
                }
                if (s5 !== peg$FAILED) {
                  s4 = [s4, s5];
                  s3 = s4;
                } else {
                  peg$currPos = s3;
                  s3 = peg$c1;
                }
              } else {
                peg$currPos = s3;
                s3 = peg$c1;
              }
              if (s3 === peg$FAILED) {
                s3 = peg$c2;
              }
              if (s3 !== peg$FAILED) {
                peg$reportedPos = s0;
                s1 = peg$c72(s1, s2, s3);
                s0 = s1;
              } else {
                peg$currPos = s0;
                s0 = peg$c1;
              }
            } else {
              peg$currPos = s0;
              s0 = peg$c1;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$c1;
          }
          if (s0 === peg$FAILED) {
            s0 = peg$currPos;
            if (input.charCodeAt(peg$currPos) === 34) {
              s1 = peg$c73;
              peg$currPos++;
            } else {
              s1 = peg$FAILED;
              if (peg$silentFails === 0) { peg$fail(peg$c74); }
            }
            if (s1 !== peg$FAILED) {
              s2 = [];
              s3 = peg$currPos;
              if (input.substr(peg$currPos, 2) === peg$c75) {
                s4 = peg$c75;
                peg$currPos += 2;
              } else {
                s4 = peg$FAILED;
                if (peg$silentFails === 0) { peg$fail(peg$c76); }
              }
              if (s4 !== peg$FAILED) {
                peg$reportedPos = s3;
                s4 = peg$c77();
              }
              s3 = s4;
              if (s3 === peg$FAILED) {
                s3 = peg$currPos;
                if (input.charCodeAt(peg$currPos) === 92) {
                  s4 = peg$c78;
                  peg$currPos++;
                } else {
                  s4 = peg$FAILED;
                  if (peg$silentFails === 0) { peg$fail(peg$c79); }
                }
                if (s4 !== peg$FAILED) {
                  if (peg$c80.test(input.charAt(peg$currPos))) {
                    s5 = input.charAt(peg$currPos);
                    peg$currPos++;
                  } else {
                    s5 = peg$FAILED;
                    if (peg$silentFails === 0) { peg$fail(peg$c81); }
                  }
                  if (s5 !== peg$FAILED) {
                    peg$reportedPos = s3;
                    s4 = peg$c82(s5);
                    s3 = s4;
                  } else {
                    peg$currPos = s3;
                    s3 = peg$c1;
                  }
                } else {
                  peg$currPos = s3;
                  s3 = peg$c1;
                }
                if (s3 === peg$FAILED) {
                  if (peg$c80.test(input.charAt(peg$currPos))) {
                    s3 = input.charAt(peg$currPos);
                    peg$currPos++;
                  } else {
                    s3 = peg$FAILED;
                    if (peg$silentFails === 0) { peg$fail(peg$c81); }
                  }
                }
              }
              while (s3 !== peg$FAILED) {
                s2.push(s3);
                s3 = peg$currPos;
                if (input.substr(peg$currPos, 2) === peg$c75) {
                  s4 = peg$c75;
                  peg$currPos += 2;
                } else {
                  s4 = peg$FAILED;
                  if (peg$silentFails === 0) { peg$fail(peg$c76); }
                }
                if (s4 !== peg$FAILED) {
                  peg$reportedPos = s3;
                  s4 = peg$c77();
                }
                s3 = s4;
                if (s3 === peg$FAILED) {
                  s3 = peg$currPos;
                  if (input.charCodeAt(peg$currPos) === 92) {
                    s4 = peg$c78;
                    peg$currPos++;
                  } else {
                    s4 = peg$FAILED;
                    if (peg$silentFails === 0) { peg$fail(peg$c79); }
                  }
                  if (s4 !== peg$FAILED) {
                    if (peg$c80.test(input.charAt(peg$currPos))) {
                      s5 = input.charAt(peg$currPos);
                      peg$currPos++;
                    } else {
                      s5 = peg$FAILED;
                      if (peg$silentFails === 0) { peg$fail(peg$c81); }
                    }
                    if (s5 !== peg$FAILED) {
                      peg$reportedPos = s3;
                      s4 = peg$c82(s5);
                      s3 = s4;
                    } else {
                      peg$currPos = s3;
                      s3 = peg$c1;
                    }
                  } else {
                    peg$currPos = s3;
                    s3 = peg$c1;
                  }
                  if (s3 === peg$FAILED) {
                    if (peg$c80.test(input.charAt(peg$currPos))) {
                      s3 = input.charAt(peg$currPos);
                      peg$currPos++;
                    } else {
                      s3 = peg$FAILED;
                      if (peg$silentFails === 0) { peg$fail(peg$c81); }
                    }
                  }
                }
              }
              if (s2 !== peg$FAILED) {
                if (input.charCodeAt(peg$currPos) === 34) {
                  s3 = peg$c73;
                  peg$currPos++;
                } else {
                  s3 = peg$FAILED;
                  if (peg$silentFails === 0) { peg$fail(peg$c74); }
                }
                if (s3 !== peg$FAILED) {
                  peg$reportedPos = s0;
                  s1 = peg$c83(s2);
                  s0 = s1;
                } else {
                  peg$currPos = s0;
                  s0 = peg$c1;
                }
              } else {
                peg$currPos = s0;
                s0 = peg$c1;
              }
            } else {
              peg$currPos = s0;
              s0 = peg$c1;
            }
          }
        }
      }
      peg$silentFails--;
      if (s0 === peg$FAILED) {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) { peg$fail(peg$c59); }
      }

      return s0;
    }

    function peg$parsenode() {
      var s0, s1;

      s0 = peg$currPos;
      if (input.substr(peg$currPos, 4).toLowerCase() === peg$c84) {
        s1 = input.substr(peg$currPos, 4);
        peg$currPos += 4;
      } else {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) { peg$fail(peg$c85); }
      }
      if (s1 !== peg$FAILED) {
        peg$reportedPos = s0;
        s1 = peg$c86(s1);
      }
      s0 = s1;

      return s0;
    }

    function peg$parseedge() {
      var s0, s1;

      s0 = peg$currPos;
      if (input.substr(peg$currPos, 4).toLowerCase() === peg$c87) {
        s1 = input.substr(peg$currPos, 4);
        peg$currPos += 4;
      } else {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) { peg$fail(peg$c88); }
      }
      if (s1 !== peg$FAILED) {
        peg$reportedPos = s0;
        s1 = peg$c86(s1);
      }
      s0 = s1;

      return s0;
    }

    function peg$parsegraph() {
      var s0, s1;

      s0 = peg$currPos;
      if (input.substr(peg$currPos, 5).toLowerCase() === peg$c89) {
        s1 = input.substr(peg$currPos, 5);
        peg$currPos += 5;
      } else {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) { peg$fail(peg$c90); }
      }
      if (s1 !== peg$FAILED) {
        peg$reportedPos = s0;
        s1 = peg$c86(s1);
      }
      s0 = s1;

      return s0;
    }

    function peg$parsedigraph() {
      var s0, s1;

      s0 = peg$currPos;
      if (input.substr(peg$currPos, 7).toLowerCase() === peg$c91) {
        s1 = input.substr(peg$currPos, 7);
        peg$currPos += 7;
      } else {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) { peg$fail(peg$c92); }
      }
      if (s1 !== peg$FAILED) {
        peg$reportedPos = s0;
        s1 = peg$c86(s1);
      }
      s0 = s1;

      return s0;
    }

    function peg$parsesubgraph() {
      var s0, s1;

      s0 = peg$currPos;
      if (input.substr(peg$currPos, 8).toLowerCase() === peg$c93) {
        s1 = input.substr(peg$currPos, 8);
        peg$currPos += 8;
      } else {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) { peg$fail(peg$c94); }
      }
      if (s1 !== peg$FAILED) {
        peg$reportedPos = s0;
        s1 = peg$c86(s1);
      }
      s0 = s1;

      return s0;
    }

    function peg$parsestrict() {
      var s0, s1;

      s0 = peg$currPos;
      if (input.substr(peg$currPos, 6).toLowerCase() === peg$c95) {
        s1 = input.substr(peg$currPos, 6);
        peg$currPos += 6;
      } else {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) { peg$fail(peg$c96); }
      }
      if (s1 !== peg$FAILED) {
        peg$reportedPos = s0;
        s1 = peg$c86(s1);
      }
      s0 = s1;

      return s0;
    }

    function peg$parsegraphType() {
      var s0, s1;

      s0 = peg$parsegraph();
      if (s0 === peg$FAILED) {
        s0 = peg$currPos;
        s1 = peg$parsedigraph();
        if (s1 !== peg$FAILED) {
          peg$reportedPos = s0;
          s1 = peg$c97(s1);
        }
        s0 = s1;
      }

      return s0;
    }

    function peg$parsewhitespace() {
      var s0, s1;

      peg$silentFails++;
      s0 = [];
      if (peg$c99.test(input.charAt(peg$currPos))) {
        s1 = input.charAt(peg$currPos);
        peg$currPos++;
      } else {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) { peg$fail(peg$c100); }
      }
      if (s1 !== peg$FAILED) {
        while (s1 !== peg$FAILED) {
          s0.push(s1);
          if (peg$c99.test(input.charAt(peg$currPos))) {
            s1 = input.charAt(peg$currPos);
            peg$currPos++;
          } else {
            s1 = peg$FAILED;
            if (peg$silentFails === 0) { peg$fail(peg$c100); }
          }
        }
      } else {
        s0 = peg$c1;
      }
      peg$silentFails--;
      if (s0 === peg$FAILED) {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) { peg$fail(peg$c98); }
      }

      return s0;
    }

    function peg$parsecomment() {
      var s0, s1, s2, s3, s4, s5;

      peg$silentFails++;
      s0 = peg$currPos;
      if (input.substr(peg$currPos, 2) === peg$c102) {
        s1 = peg$c102;
        peg$currPos += 2;
      } else {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) { peg$fail(peg$c103); }
      }
      if (s1 !== peg$FAILED) {
        s2 = [];
        if (peg$c104.test(input.charAt(peg$currPos))) {
          s3 = input.charAt(peg$currPos);
          peg$currPos++;
        } else {
          s3 = peg$FAILED;
          if (peg$silentFails === 0) { peg$fail(peg$c105); }
        }
        while (s3 !== peg$FAILED) {
          s2.push(s3);
          if (peg$c104.test(input.charAt(peg$currPos))) {
            s3 = input.charAt(peg$currPos);
            peg$currPos++;
          } else {
            s3 = peg$FAILED;
            if (peg$silentFails === 0) { peg$fail(peg$c105); }
          }
        }
        if (s2 !== peg$FAILED) {
          s1 = [s1, s2];
          s0 = s1;
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$c1;
      }
      if (s0 === peg$FAILED) {
        s0 = peg$currPos;
        if (input.substr(peg$currPos, 2) === peg$c106) {
          s1 = peg$c106;
          peg$currPos += 2;
        } else {
          s1 = peg$FAILED;
          if (peg$silentFails === 0) { peg$fail(peg$c107); }
        }
        if (s1 !== peg$FAILED) {
          s2 = [];
          s3 = peg$currPos;
          s4 = peg$currPos;
          peg$silentFails++;
          if (input.substr(peg$currPos, 2) === peg$c108) {
            s5 = peg$c108;
            peg$currPos += 2;
          } else {
            s5 = peg$FAILED;
            if (peg$silentFails === 0) { peg$fail(peg$c109); }
          }
          peg$silentFails--;
          if (s5 === peg$FAILED) {
            s4 = peg$c30;
          } else {
            peg$currPos = s4;
            s4 = peg$c1;
          }
          if (s4 !== peg$FAILED) {
            if (input.length > peg$currPos) {
              s5 = input.charAt(peg$currPos);
              peg$currPos++;
            } else {
              s5 = peg$FAILED;
              if (peg$silentFails === 0) { peg$fail(peg$c110); }
            }
            if (s5 !== peg$FAILED) {
              s4 = [s4, s5];
              s3 = s4;
            } else {
              peg$currPos = s3;
              s3 = peg$c1;
            }
          } else {
            peg$currPos = s3;
            s3 = peg$c1;
          }
          while (s3 !== peg$FAILED) {
            s2.push(s3);
            s3 = peg$currPos;
            s4 = peg$currPos;
            peg$silentFails++;
            if (input.substr(peg$currPos, 2) === peg$c108) {
              s5 = peg$c108;
              peg$currPos += 2;
            } else {
              s5 = peg$FAILED;
              if (peg$silentFails === 0) { peg$fail(peg$c109); }
            }
            peg$silentFails--;
            if (s5 === peg$FAILED) {
              s4 = peg$c30;
            } else {
              peg$currPos = s4;
              s4 = peg$c1;
            }
            if (s4 !== peg$FAILED) {
              if (input.length > peg$currPos) {
                s5 = input.charAt(peg$currPos);
                peg$currPos++;
              } else {
                s5 = peg$FAILED;
                if (peg$silentFails === 0) { peg$fail(peg$c110); }
              }
              if (s5 !== peg$FAILED) {
                s4 = [s4, s5];
                s3 = s4;
              } else {
                peg$currPos = s3;
                s3 = peg$c1;
              }
            } else {
              peg$currPos = s3;
              s3 = peg$c1;
            }
          }
          if (s2 !== peg$FAILED) {
            if (input.substr(peg$currPos, 2) === peg$c108) {
              s3 = peg$c108;
              peg$currPos += 2;
            } else {
              s3 = peg$FAILED;
              if (peg$silentFails === 0) { peg$fail(peg$c109); }
            }
            if (s3 !== peg$FAILED) {
              s1 = [s1, s2, s3];
              s0 = s1;
            } else {
              peg$currPos = s0;
              s0 = peg$c1;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$c1;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$c1;
        }
      }
      peg$silentFails--;
      if (s0 === peg$FAILED) {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) { peg$fail(peg$c101); }
      }

      return s0;
    }

    function peg$parse_() {
      var s0;

      s0 = peg$parsewhitespace();
      if (s0 === peg$FAILED) {
        s0 = peg$parsecomment();
      }

      return s0;
    }


      var _ = require("./lodash");
      var directed;


    peg$result = peg$startRuleFunction();

    if (peg$result !== peg$FAILED && peg$currPos === input.length) {
      return peg$result;
    } else {
      if (peg$result !== peg$FAILED && peg$currPos < input.length) {
        peg$fail({ type: "end", description: "end of input" });
      }

      throw peg$buildException(null, peg$maxFailExpected, peg$maxFailPos);
    }
  }

  return {
    SyntaxError: SyntaxError,
    parse:       parse
  };
})();

},{"./lodash":6}],5:[function(require,module,exports){
/* global window */

var graphlib;

if (require) {
  try {
    graphlib = require("graphlib");
  } catch (e) {}
}

if (!graphlib) {
  graphlib = window.graphlib;
}

module.exports = graphlib;

},{"graphlib":undefined}],6:[function(require,module,exports){
/* global window */

var lodash;

if (require) {
  try {
    lodash = require("lodash");
  } catch (e) {}
}

if (!lodash) {
  lodash = window._;
}

module.exports = lodash;

},{"lodash":undefined}],7:[function(require,module,exports){
var _ = require("./lodash"),
    grammar = require("./dot-grammar"),
    buildGraph = require("./build-graph");

module.exports = function readMany(str) {
  var parseTree = grammar.parse(str);
  return _.map(parseTree, buildGraph);
};

},{"./build-graph":3,"./dot-grammar":4,"./lodash":6}],8:[function(require,module,exports){
var grammar = require("./dot-grammar"),
    buildGraph = require("./build-graph");

module.exports = function readOne(str) {
  var parseTree = grammar.parse(str, { startRule: "graphStmt" });
  return buildGraph(parseTree);
};


},{"./build-graph":3,"./dot-grammar":4}],9:[function(require,module,exports){
module.exports = '0.6.0';

},{}],10:[function(require,module,exports){
var _ = require("./lodash");

module.exports = writeOne;

var UNESCAPED_ID_PATTERN = /^[a-zA-Z\200-\377_][a-zA-Z\200-\377_0-9]*$/;

function writeOne(g) {
  var ec = g.isDirected() ? "->" : "--",
      writer = new Writer();

  if (!g.isMultigraph()) {
    writer.write("strict ");
  }

  writer.writeLine((g.isDirected() ? "digraph" : "graph") + " {");
  writer.indent();

  var graphAttrs = g.graph();
  if (_.isObject(graphAttrs)) {
    _.each(graphAttrs, function(v, k) {
      writer.writeLine(id(k) + "=" + id(v) + ";");
    });
  }

  writeSubgraph(g, undefined, writer);

  g.edges().forEach(function(edge) {
    writeEdge(g, edge, ec, writer);
  });

  writer.unindent();
  writer.writeLine("}");

  return writer.toString();
}

function writeSubgraph(g, v, writer) {
  var children = g.isCompound() ? g.children(v) : g.nodes();
  _.each(children, function(w) {
    if (!g.isCompound() || !g.children(w).length) {
      writeNode(g, w, writer);
    } else {
      writer.writeLine("subgraph " + id(w) + " {");
      writer.indent();

      if (_.isObject(g.node(w))) {
        _.map(g.node(w), function(val, key) {
          writer.writeLine(id(key) + "=" + id(val) + ";");
        });
      }

      writeSubgraph(g, w, writer);
      writer.unindent();
      writer.writeLine("}");
    }
  });
}

function writeNode(g, v, writer) {
  writer.write(id(v));
  writeAttrs(g.node(v), writer);
  writer.writeLine();
}

function writeEdge(g, edge, ec, writer) {
  var v = edge.v,
      w = edge.w,
      attrs = g.edge(edge);

  writer.write(id(v) + " " + ec + " " + id(w));
  writeAttrs(attrs, writer);
  writer.writeLine();
}

function writeAttrs(attrs, writer) {
  if (_.isObject(attrs)) {
    var attrStrs = _.map(attrs, function(val, key) {
      return id(key) + "=" + id(val);
    });
    if (attrStrs.length) {
      writer.write(" [" + attrStrs.join(",") + "]");
    }
  }
}

function id(obj) {
  if (typeof obj === "number" || obj.toString().match(UNESCAPED_ID_PATTERN)) {
    return obj;
  }

  return "\"" + obj.toString().replace(/"/g, "\\\"") + "\"";
}

// Helper object for making a pretty printer
function Writer() {
  this._indent = "";
  this._content = "";
  this._shouldIndent = true;
}

Writer.prototype.INDENT = "  ";

Writer.prototype.indent = function() {
  this._indent += this.INDENT;
};

Writer.prototype.unindent = function() {
  this._indent = this._indent.slice(this.INDENT.length);
};

Writer.prototype.writeLine = function(line) {
  this.write((line || "") + "\n");
  this._shouldIndent = true;
};

Writer.prototype.write = function(str) {
  if (this._shouldIndent) {
    this._shouldIndent = false;
    this._content += this._indent;
  }
  this._content += str;
};

Writer.prototype.toString = function() {
  return this._content;
};


},{"./lodash":6}]},{},[1]);
