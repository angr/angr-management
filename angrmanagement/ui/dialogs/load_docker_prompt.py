from PySide2.QtWidgets import QInputDialog, QMessageBox

import subprocess
import logging


_l = logging.getLogger(__name__)


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
    # Try to list docker images, handle failure cases
    try:
        output = subprocess.check_output(['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'])
    except FileNotFoundError as e:
        _l.error('Docker not found.')
        QMessageBox(parent).critical(None, 'Docker not found', 'Make sure docker is installed and in your path')
        raise LoadDockerPromptError
    except subprocess.CalledProcessError:
        _l.error('Docker images failed: Make sure you are have privileges.')
        QMessageBox(parent).critical(None, 'docker images failed to run', 'Are you root? Docker needs root!')
        raise LoadDockerPromptError

    items = output.decode('utf-8').split('\n')
    return [ i for i in items if i and '<none>' not in i ]
