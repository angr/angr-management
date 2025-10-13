from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QLineEdit, QPlainTextEdit, QWidget


class QInsightGeneric(QWidget):
    def __init__(self, name: str, items: list[str], name_width: int = 200, content_height: int = 200, parent=None):
        super().__init__(parent)

        self.name = name
        self.items = items
        self.name_width = name_width
        self.content_height = content_height

        self._init_widgets()

    def _init_widgets(self):

        label = QLineEdit()
        label.setText(self.name)
        label.setFixedWidth(self.name_width)

        content = QPlainTextEdit()
        all_text = []
        for item in self.items:
            item: dict
            text = []
            if "func_addr" in item:
                if item.get("func_name", None):
                    text += ["Inside function %s (%#x)" % (item["func_name"], item["func_addr"])]
                else:
                    text += ["Inside function %#x" % item["func_addr"]]
            if "ref_at" in item:
                text += ["Referenced at block %#x" % item["ref_at"]]
            text += [item["description"]]
            text = "\n".join(text)
            all_text.append(text)
        content.setPlainText("\n\n".join(all_text))
        content.setFixedHeight(self.content_height)

        layout = QHBoxLayout()
        layout.addWidget(label)
        layout.addWidget(content)
        self.setLayout(layout)
