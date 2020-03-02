
from PySide2.QtGui import QPainter
from PySide2.QtCore import Qt, QRectF

from angr.sim_type import SimType, SimTypeFunction, SimTypePointer
from angr.calling_conventions import SimRegArg

from .qgraph_object import QCachedGraphicsItem


class PrototypeArgument:

    __slots__ = ('ty', 'ty_pos', 'ty_width', 'arg', 'arg_pos', 'arg_width', )

    def __init__(self, ty, ty_pos, ty_width, arg, arg_pos, arg_width):
        self.ty = ty
        self.ty_pos = ty_pos
        self.ty_width = ty_width
        self.arg = arg
        self.arg_pos = arg_pos
        self.arg_width = arg_width

    def width(self):
        if self.arg is not None:
            return self.arg_pos[0] + self.arg_width - self.ty_pos[0]
        else:
            return self.ty_width


class QFunctionHeader(QCachedGraphicsItem):

    def __init__(self, addr, name, prototype, args, config, disasm_view, workspace, parent=None):
        super().__init__(parent=parent)

        self.workspace = workspace
        self.addr = addr
        self.name = name
        self.prototype = prototype  # type: SimTypeFunction
        self.args = args

        self._config = config
        self._disasm_view = disasm_view

        self._name_width = None
        self._return_type_width = None
        self._prototype_args = [ ]
        self._arg_str_list = None
        self._args_str = None
        self._args_str_width = None

        self._init_widgets()

    def paint(self, painter, option, widget):
        painter.setRenderHints(
                QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)
        painter.setFont(self._config.code_font)
        painter.setPen(Qt.blue)

        font_ascent = self._config.disasm_font_ascent
        font_metrics = self._config.disasm_font_metrics

        x = 0
        y = 0

        x, y, _ = self._paint_prototype(x, y, painter=painter)

        # args
        painter.setPen(Qt.darkBlue)
        x = 0
        y += self._config.disasm_font_height
        if self._arg_str_list is not None:
            prefix = 'Args: ('
            painter.drawText(x, y + font_ascent, prefix)
            x += font_metrics.width(prefix)

            for i, arg_str in enumerate(self._arg_str_list):
                painter.drawText(x, y + font_ascent, arg_str)
                x += font_metrics.width(arg_str)
                if i < len(self._arg_str_list) - 1:
                    painter.drawText(x, y + font_ascent, ", ")
                    x += font_metrics.width(", ")

            painter.drawText(x, y + font_ascent, ")")

    def _paint_prototype(self, x, y, painter=None):

        _x = x
        font_ascent = self._config.disasm_font_ascent
        font_metrics = self._config.disasm_font_metrics

        if self.prototype is None:
            # function name
            if painter: painter.drawText(x, y + font_ascent, self.name)
            x += font_metrics.width(self.name)

        else:
            # type of the return value
            rt = self._type2str(self.prototype.returnty)
            self._return_type_width = font_metrics.width(rt)
            if painter: painter.drawText(x, y + font_ascent, rt)
            x += self._return_type_width

            # space
            x += font_metrics.width(" ")

            # function name
            if painter: painter.drawText(x, y + font_ascent, self.name)
            x += font_metrics.width(self.name)

            # left parenthesis
            if painter: painter.drawText(x, y + font_ascent, "(")
            x += font_metrics.width("(")

            # arguments
            self._prototype_args = [ ]
            for i, arg_type in enumerate(self.prototype.args):
                type_str = self._type2str(arg_type)
                type_str_width = font_metrics.width(type_str)

                if self.prototype.arg_names and i < len(self.prototype.arg_names):
                    arg_name = self.prototype.arg_names[i]
                else:
                    arg_name = "arg_%d" % i
                arg_name_width = font_metrics.width(arg_name)

                proto_arg = PrototypeArgument(
                    type_str,
                    (x, y + font_ascent),
                    type_str_width,
                    arg_name,
                    (x + type_str_width + font_metrics.width(" "), y + font_ascent),
                    arg_name_width,
                )
                self._prototype_args.append(proto_arg)

                if painter: painter.drawText(x, y + font_ascent, type_str)
                x += type_str_width + font_metrics.width(" ")
                if painter: painter.drawText(x, y + font_ascent, arg_name)
                x += arg_name_width

                if i < len(self.prototype.args) - 1:
                    # splitter
                    if painter: painter.drawText(x, y + font_ascent, ", ")
                    x += font_metrics.width(", ")

            # right parenthesis
            if painter: painter.drawText(x, y + font_ascent, ")")
            x += font_metrics.width(")")

        return x, y, x - _x

    def _init_widgets(self):
        _, _, self._prototype_width = self._paint_prototype(0, 0)
        self._name_width = self._config.disasm_font_metrics.width(self.name)

        if self.args is not None:
            self._arg_str_list = [ ]
            for arg in self.args:
                if isinstance(arg, SimRegArg):
                    self._arg_str_list.append(arg.reg_name)
                else:
                    self._arg_str_list.append(str(arg))

            self._args_str = "Args: (%s)" % (", ".join(self._arg_str_list))
        else:
            self._args_str = ""

        self._args_str_width = self._config.disasm_font_metrics.width(self._args_str)

    def _boundingRect(self):
        height = self._config.disasm_font_height
        if self._args_str:
            height += self._config.disasm_font_height

        width = max(
            self._prototype_width,
            self._args_str_width,
        )

        return QRectF(0, 0, width, height)

    def _type2str(self, ty):
        """
        Convert a SimType instance to a string that can be displayed.

        :param SimType ty:  The SimType instance.
        :return:            A string.
        :rtype:             str
        """

        if isinstance(ty, SimTypePointer):
            return "{}*".format(self._type2str(ty.pts_to))
        if ty.label:
            return ty.label
        return repr(ty)
