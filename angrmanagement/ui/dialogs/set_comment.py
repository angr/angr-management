from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QPlainTextEdit
from PySide2.QtCore import Qt


class CommentTextBox(QPlainTextEdit):
    def __init__(self, textchanged_callback=None, parent=None):
        super(CommentTextBox, self).__init__(parent)
        if textchanged_callback is not None:
            self.textChanged.connect(textchanged_callback)

    @property
    def text(self):
        text = self.toPlainText()
        if text is not None:
            return text.strip()
        return None


class SetComment(QDialog):
    def __init__(self, disasm_view, comment_addr, parent=None):
        super(SetComment, self).__init__(parent)

        # initialization
        self._disasm_view = disasm_view
        self._comment_addr = comment_addr

        self._comment_textbox = None

        self.setWindowTitle('Set Comment')
        self.main_layout = QVBoxLayout()
        self._init_widgets()
        self.setLayout(self.main_layout)

    #
    # Private methods
    #

    def _init_widgets(self):

        # name label
        comment_lbl = QLabel(self)
        comment_lbl.setText('Comment text')

        # comment textbox
        comment_txtbox = CommentTextBox(parent=self)
        if self._comment_addr in self._disasm_view.disasm.kb.comments:
            comment_txtbox.setPlainText(self._disasm_view.disasm.kb.comments[self._comment_addr])
            comment_txtbox.selectAll()
        self._comment_textbox = comment_txtbox

        comment_layout = QVBoxLayout()
        comment_layout.addWidget(comment_lbl)
        comment_layout.addWidget(comment_txtbox)
        self.main_layout.addLayout(comment_layout)

        # buttons
        ok_button = QPushButton(self)
        ok_button.setText('OK')
        ok_button.clicked.connect(self._on_ok_clicked)

        cancel_button = QPushButton(self)
        cancel_button.setText('Cancel')
        cancel_button.clicked.connect(self._on_cancel_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)

        self.main_layout.addLayout(buttons_layout)

    #
    # Event handlers
    #

    def _on_ok_clicked(self):
        comment_txt = self._comment_textbox.text
        self._disasm_view.set_comment(self._comment_addr, comment_txt)
        self.close()

    def _on_cancel_clicked(self):
        self.close()
