# pylint:disable=global-statement,missing-class-docstring,no-self-use,unspecified-encoding
import os
import sys
import subprocess
import logging
from pathlib import Path
from typing import Tuple, Optional

import tomlkit
import tomlkit.exceptions
from xdg import BaseDirectory
from PySide2.QtWidgets import QApplication
from PySide2.QtWidgets import QMessageBox, QFileDialog

from angrmanagement.plugins import BasePlugin
from angrmanagement.daemon.url_handler import UrlActionBase, register_url_action
from angrmanagement.daemon.server import register_server_exposed_method

_l = logging.getLogger(name=__name__)

# we probably want to put this feature into angr management
_app = None

def tmp_app():
    global _app
    if _app is None:
        _app = QApplication()
    return _app


class UrlActionOpenSourceFile(UrlActionBase):

    def __init__(self,
                 target_uuid: str,
                 challenge_name: str,
                 source_file: str,
                 line_number: str,
                 position: str,
                 editor: str):
        super().__init__()

        self.target_uuid = target_uuid
        self.challenge_name = challenge_name
        self.source_file = source_file
        self.editor = editor

        # TODO: Parse line number and position
        self.line_number = line_number
        self.position = position

    def act(self, daemon_conn=None):
        daemon_conn.root.open_source_file(
            self.target_uuid,
            self.challenge_name,
            self.source_file,
            self.line_number,
            self.position,
            self.editor,
        )

    @classmethod
    def _from_params(cls, params):
        return cls(
            cls._one_param(params, 'target_uuid'),
            cls._one_param(params, 'challenge_name'),
            cls._one_param(params, 'source_file'),
            cls._one_param(params, 'line_number'),
            cls._one_param(params, 'position'),
            cls._one_param(params, 'editor'),
        )


class ChessUrlHandler(BasePlugin):
    DISPLAY_NAME = "CHESS URL Handler"
    REQUIRE_WORKSPACE = False

    def __init__(self, workspace):
        super().__init__(workspace)

        self._register_url_handlers()

    def _register_url_handlers(self):
        register_url_action('open_source_file', UrlActionOpenSourceFile)
        register_server_exposed_method("open_source_file", self.exposed_open_source_file)

    def _get_rootdir_config_path(self) -> str:
        am_root = BaseDirectory.save_config_path('angr-management')
        if am_root is not None:
            rootdirs_path = os.path.join(am_root, "challenge_rootdirs.toml")
            return rootdirs_path
        raise ValueError("Cannot get the configuration file root directory for angr-management.")

    def _get_rootdir(self, target_uuid: str, challenge_name: str,
                     source_file: str) -> Tuple[Optional[str],Optional[str]]:
        rootdirs_path = self._get_rootdir_config_path()
        # load it if it exists
        entries = { }
        if os.path.isfile(rootdirs_path):
            with open(rootdirs_path, "r") as f:
                try:
                    entries = tomlkit.load(f)
                except tomlkit.exceptions.ParseError:
                    _l.error("Cannot decode rootdirs file %s. Ignore existing content.",
                             rootdirs_path)

        dir_path = None
        if 'uuid_to_rootdir' in entries:
            if target_uuid in entries['uuid_to_rootdir']:
                # yes there is already one
                dir_path = entries['uuid_to_rootdir'][target_uuid].value
            else:
                dir_path = None

        while True:
            # test the existing dir_path for the existence of the file
            if dir_path:
                if not source_file:
                    # source file is not specified. we take whatever is there!
                    return dir_path, None

                file_found = False
                full_path = None

                source_file_name = os.path.basename(source_file)
                for base, _, files in os.walk(dir_path):
                    if source_file_name in files:
                        # check the full path
                        full_path = os.path.normpath(os.path.join(base, source_file_name))
                        if full_path.endswith(source_file):
                            # found it!
                            file_found = True
                            break

                if file_found:
                    return dir_path, full_path

            # we either did not find the file under the specified directory or got a wrong directory to start with
            # ask the user to manually specify a directory
            tmp_app()
            QMessageBox.information(
                None,
                "Specifying the root directory",
                f"File {source_file} is not found under the directory you specified.\n\n"
                f"You will be asked to specify the challenge root directory for target {target_uuid} "
                f"({challenge_name}). We will then open the specified source code file for you.\n"
                f"We will only ask you once per target ID. Your selection will be stored on this machine.",
            )
            dir_path = QFileDialog.getExistingDirectory(
                None,
                f"Specifying the root directory for target {target_uuid} ({challenge_name})",
                # TODO: Use the default challenge root directory
                str(Path.home()),
                QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks,
            )
            if not dir_path:
                # the user did not specify anything
                return None, None

            # loop back to test the validity of the provided root directory

    def _save_rootdir(self, target_uuid: str, challenge_name: str, root_dir: str):
        rootdirs_path = self._get_rootdir_config_path()
        # load it
        entries = { }
        if os.path.isfile(rootdirs_path):
            with open(rootdirs_path, "r") as f:
                try:
                    entries = tomlkit.load(f)
                except tomlkit.exceptions.ParseError:
                    _l.error("Cannot decode rootdirs file %s. Ignore existing content.",
                             rootdirs_path)

        if 'uuid_to_challenge' not in entries:
            entries['uuid_to_challenge'] = { }
        if 'uuid_to_rootdir' not in entries:
            entries['uuid_to_rootdir'] = { }
        entries['uuid_to_challenge'][target_uuid] = challenge_name
        entries['uuid_to_rootdir'][target_uuid] = root_dir

        # store it
        with open(rootdirs_path, "w") as f:
            tomlkit.dump(entries, f)

    def _vscode_path(self) -> Optional[str]:
        if sys.platform == "win32":
            default_locations = [
                os.path.join(os.getenv("LOCALAPPDATA"), "Programs", "Microsoft VS Code"),
            ]
            default_locations += os.getenv("PATH").split(";")
            code_exe = "code.exe"
        elif sys.platform == "linux":
            # assuming code is within PATH
            return "code"
        elif sys.platform == "darwin":
            # try the default path
            raise NotImplementedError()
        else:
            raise NotImplementedError()

        for loc in default_locations:
            vscode_path = os.path.join(loc, code_exe)
            if os.path.isfile(vscode_path):
                # found it!
                if sys.platform in ("linux", "darwin"):
                    return vscode_path

        return None

    def exposed_open_source_file(self, target_uuid: str, challenge_name: str, source_file: str, line_number: int,
                                 position: int, editor: str) -> None:
        # Find the root directory of the challenge
        # if this is the first time we see a challenge name, ask the user to specify the challenge root directory
        root_dir, file_path = self._get_rootdir(target_uuid, challenge_name, source_file)

        if not root_dir:
            return

        # log the root dir for the given target UUID and challenge_name
        self._save_rootdir(target_uuid, challenge_name, root_dir)

        if not file_path:
            return

        # invoke the corresponding editor
        if editor == "vscode":
            # https://code.visualstudio.com/docs/editor/command-line#_opening-files-and-folders
            vscode = self._vscode_path()
            if vscode:
                cmd_line = [vscode, "-g", f"{file_path}:{line_number}:{position}"]
                subprocess.Popen(cmd_line, close_fds=True)
            else:
                tmp_app()
                QMessageBox.critical(
                    None,
                    "VSCode is not found",
                    "Cannot find the executable for VS Code."
                )
                return

        elif editor == "am":
            raise NotImplementedError()

        else:
            # fallback to the default editor
            raise NotImplementedError()
