import logging

from PySide2.QtWidgets import QInputDialog

import subprocess


class LoadDockerPrompt(QInputDialog):
    def __init__(self, parent=None):
        super(LoadDockerPrompt, self).__init__(parent)

        self.setComboBoxItems(get_docker_images())
        self.setOption(QInputDialog.UsePlainTextEditForTextInput, True)
        self.setLabelText('Select a docker target')
        self.setComboBoxEditable(False)
        self.setModal(True)

def get_docker_images():
    output = subprocess.check_output(['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'])
    items = output.decode('utf-8').split('\n')
    return [ i for i in items if i and '<none>' not in i ]
