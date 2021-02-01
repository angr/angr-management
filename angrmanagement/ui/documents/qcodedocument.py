
from PySide2.QtGui import QTextDocument
from PySide2.QtWidgets import QPlainTextDocumentLayout

from angr.analyses.decompiler.structured_codegen import CConstant, CVariable, CFunctionCall, StructuredCodeGenerator, \
    CStructField, CStatement, CExpression, CClosingObject

from ...config import Conf


class QCodeDocument(QTextDocument):
    """
    QTextDocument class for pseudocode generated by StructuredCodeGenerator analysis in angr.
    """
    def __init__(self, codegen):
        super().__init__()

        self._codegen = codegen  # type: StructuredCodeGenerator

        # default font
        self.setDefaultFont(Conf.code_font)

        self.setPlainText(self._codegen.text)
        self.setDocumentLayout(QPlainTextDocumentLayout(self))

    @property
    def posmap(self):
        """

        :return:
        :rtype:     Optional[PositionMapping]
        """
        if self._codegen is None:
            return None
        return self._codegen.posmap

    @property
    def nodemap(self):
        if self._codegen is None:
            return None
        return self._codegen.nodemap

    def get_node_at_position(self, pos):
        if self._codegen is not None and self._codegen.posmap is not None:
            n = self._codegen.posmap.get_node(pos)
            if n is None:
                n = self._codegen.posmap.get_node(pos - 1)
            return n

        return None

    def get_stmt_node_at_position(self, pos):
        """
        Iteratively finds the first valid node inside the GUI display that is not None.
        Finds the node based on the postion given (usually related to the mouse location).
        The function can return any valid Cxxx class inside the angr decompiler.

        Algorithm: O(n)
        This algorithm will search the position map by alternating between extended it's left and right search
        until we either hit the EOL or newline on the left and right. We stop either side searching once we
        hit a newline or EOL as well. In addition, we keep a special case for when the cursor is off the screen
        to simply put it back on the screen.

        :param pos:
        :return:
        """

        if self._codegen is not None and self._codegen.stmt_posmap is not None:
            n = self._codegen.stmt_posmap.get_node(pos)

            # if we can't find a node at the current position, start the algorithm search
            # from the left and right iteratively.
            if n is None:

                # special case where cursor is off the screen, reposition to before the end
                if pos >= len(self._codegen.text) - 2:
                    l = len(self._codegen.text) - 4
                else:
                    l = pos-1

                r = pos+1
                inc_l = not self._pos_is_newline_or_oob(l)
                inc_r = not self._pos_is_newline_or_oob(r)

                # iterate until we hit start or end of document
                while inc_l or inc_r:

                    # continue left search if we are still at a valid char
                    if inc_l:
                        n = self._codegen.stmt_posmap.get_node(l)
                        if n is not None:
                            break
                        l -= 1
                        inc_l = not self._pos_is_newline_or_oob(l)

                    # continue right search if we are still at a valid char
                    if inc_r:
                        n = self._codegen.stmt_posmap.get_node(r)
                        if n is not None:
                            break
                        r += 1
                        inc_r = not self._pos_is_newline_or_oob(r)

            return n

    def find_closest_node_pos(self, ins_addr):
        return self._codegen.insmap.get_nearest_pos(ins_addr)

    def find_related_text_chunks(self, node):

        if self._codegen is None or self._codegen.nodemap is None:
            return None

        if isinstance(node, CConstant):
            starts = self._codegen.nodemap.get(node.value, None)
            if starts is None:
                return [ ]

        elif isinstance(node, CVariable):
            if node.unified_variable is not None:
                starts = self._codegen.nodemap.get(node.unified_variable, None)
            else:
                starts = self._codegen.nodemap.get(node.variable, None)
            if starts is None:
                return [ ]

        elif isinstance(node, CFunctionCall):
            starts = self._codegen.nodemap.get(node.callee_func if node.callee_func is not None else node.callee_target,
                                               None)
            if starts is None:
                return [ ]

        elif isinstance(node, CStructField):
            key = (node.struct_type, node.offset)
            starts = self._codegen.nodemap.get(key, None)

            if starts is None:
                return [ ]

        elif isinstance(node, CClosingObject):
            starts = self._codegen.nodemap.get(node, None)

            if starts is None:
                return [ ]

        else:
            # Unsupported
            return [ ]

        chunks = [ ]
        for start in starts:
            elem = self._codegen.posmap.get_element(start)
            if elem is None:
                continue
            chunks.append((elem.start, elem.length + elem.start))
        return chunks

    #
    #   Private Helper Functions
    #

    def _pos_is_newline_or_oob(self, pos: int):
        """
        Checks if a position is a newline or out of bounds of the
        text generated from the decompiler.

        :param pos:
        :return:
        """
        if pos >= len(self._codegen.text):
            return True

        return self._codegen.text[pos] == "\n"


