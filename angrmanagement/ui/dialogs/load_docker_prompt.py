from PySide2.QtWidgets import QInputDialog, QMessageBox

import subprocess
import logging


_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)


class LoadDockerPromptError(Exception):
    pass


class LoadDockerPrompt(QInputDialog):
    def __init__(self, parent=None):
        super(LoadDockerPrompt, self).__init__(parent)

        self.setComboBoxItems(get_docker_images(self))
        self.setOption(QInputDialog.UsePlainTextEditForTextInput, True)
        self.setLabelText('Select a docker target')
        self.setComboBoxEditable(False)
        self.setModal(True)
        _l.info('Docker prompt succesfully loaded')

def get_docker_images(parent=None):
    try:
        output = subprocess.check_output(['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'])
    except subprocess.CalledProcessError:
        _l.error('Docker images failed: Make sure you are have privileges.')
        QMessageBox(parent).critical(None, 'docker images failed to run', 'Are you root? Docker needs root!')
        raise LoadDockerPromptError
    items = output.decode('utf-8').split('\n')
    return [ i for i in items if i and '<none>' not in i ]
