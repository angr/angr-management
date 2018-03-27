
class OperandHighlightMode(object):
    SAME_IDENT = 0
    SAME_TEXT = 1


class InfoDock(object):
    def __init__(self):
        self.induction_variable_analysis = None
        self.variable_manager = None

        self.highlight_mode = OperandHighlightMode.SAME_IDENT  # default highlight mode
        self.selected_operand = None

    @property
    def smart_highlighting(self):
        return self.highlight_mode == OperandHighlightMode.SAME_IDENT

    @smart_highlighting.setter
    def smart_highlighting(self, v):
        if v:
            self.highlight_mode = OperandHighlightMode.SAME_IDENT
        else:
            self.highlight_mode = OperandHighlightMode.SAME_TEXT

    def initialize(self):
        self.selected_operand = None

    def should_highlight_operand(self, operand):
        if self.selected_operand is None:
            return False

        if self.highlight_mode == OperandHighlightMode.SAME_TEXT or self.selected_operand.variable is None:
            # when there is no related variable, we highlight as long as they have the same text
            return operand.text == self.selected_operand.text
        elif self.highlight_mode == OperandHighlightMode.SAME_IDENT:
            if self.selected_operand.variable is not None and operand.variable is not None:
                return self.selected_operand.variable.ident == operand.variable.ident

        return False
