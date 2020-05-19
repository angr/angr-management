from typing import Optional

from angrmanagement.logic.threads import is_gui_thread, gui_thread_schedule_async
from angrmanagement.plugins.base_plugin import BasePlugin

from .ui import LoadComponentsDialog, ComponentsView


class ComponentsPlugin(BasePlugin):
    REQUIRE_WORKSPACE = False

    """
    Implement a component viewer that takes JSON messages on function clustering from the server side and visualizes
    the clusters in a treeview.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.workspace is not None:
            self.view: ComponentsView = ComponentsView(self.workspace, "left")

            # register a new view
            self.workspace.view_manager.add_view(self.view, self.view.caption, self.view.category)

    def teardown(self):
        pass

    #
    # Menus
    #

    MENU_BUTTONS = [
        'Load components...',
        'Reset components',
    ]
    LOAD_COMPONENTS = 0
    RESET_COMPONENTS = 1

    def handle_click_menu(self, idx):

        if idx < 0 or idx >= len(self.MENU_BUTTONS):
            return

        if self.workspace.instance.project is None:
            return

        mapping = {
            self.LOAD_COMPONENTS: self.load_components,
            self.RESET_COMPONENTS: self.reset_components,
        }
        mapping.get(idx)()

    def load_components(self, url: Optional[str]=None):
        """
        Open a new dialog and take a JSON URL or a file path. Then load components from that URL.
        """
        dialog = LoadComponentsDialog(workspace=self.workspace, url=url)
        dialog.exec_()
        if dialog.tree is not None:
            self.view.load(dialog.tree)

    def reset_components(self):
        """
        Clear existing components information.
        """
        self.view.reset()

    #
    # URLs
    #

    # register actions
    URL_ACTIONS = [
        'bughouse_component',
    ]

    def handle_url_action(self, action, kwargs):
        mapping = {
            'bughouse_component': self.handle_url_action_bughouse_component,
        }

        func = mapping.get(action)
        if is_gui_thread():
            func(**kwargs)
        else:
            gui_thread_schedule_async(func, kwargs=kwargs)

    def handle_url_action_bughouse_component(self, url=None):
        self.load_components(url)
