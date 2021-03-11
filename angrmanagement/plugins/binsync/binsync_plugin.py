from angrmanagement.plugins import BasePlugin

from angr.sim_variable import SimStackVariable

from ...ui.workspace import Workspace
from .sync_config import SyncConfig
from .sync_view import SyncView


class BinsyncPlugin(BasePlugin):
    def __init__(self, workspace: Workspace):
        super().__init__(workspace)

        # init the Sync View on load
        self.sync_view = SyncView(workspace, 'right')
        self.workspace.add_view(self.sync_view, self.sync_view.caption, self.sync_view.category)

        self.selected_func = None

    #
    # Binsync Deinit
    #

    def teardown(self):
        # destroy the sync view on deinit
        self.workspace.remove_view(self.sync_view)

    #
    # Binsync Menus
    #

    MENU_BUTTONS = ('Configure Binsync...',)
    MENU_CONFIG_ID = 0

    def handle_click_menu(self, idx):
        # sanity check on menu selection
        if idx < 0 or idx >= len(self.MENU_BUTTONS):
            return

        if self.workspace.instance.project.am_none:
            return

        mapping = {
            self.MENU_CONFIG_ID: self.open_sync_config_dialog
        }

        # call option mapped to each menu pos
        mapping.get(idx)()

    def open_sync_config_dialog(self):
        if self.workspace.instance.project.am_none:
            # project does not exist yet
            return

        sync_config = SyncConfig(self.workspace.instance)
        sync_config.exec_()

    #
    # Binsync Interaction (Context Menu)
    #

    def build_context_menu_function(self, func): # pylint: disable=unused-argument
        # if not connected to a repo, give no options
        if self.workspace.instance.kb.sync.connected:
            # connection is live, get the context!
            self.selected_func = func

            pull_menu = []
            auto_pull_menu = []
            patch_menu = []
            for user in self.workspace.instance.sync.users:
                pull_menu.append((user.name, self.pullFunction))
                auto_pull_menu.append((user.name, self.autoPullFunction))
                patch_menu.append((user.name, self.pullPatches))

            yield ("Patch", self.pushFunction)
            yield ("Pull..", pull_menu)
            yield ("Auto Pull...", auto_pull_menu)
            yield ("Pull Patches...", patch_menu)

    def pushFunction(self):
        # function
        func = self.selected_func
        kb = self.workspace.instance.project.kb
        kb.sync.push_function(func)

        # comments
        comments = { }
        for block in func.blocks:
            for ins_addr in block.instruction_addrs:
                if ins_addr in kb.comments:
                    comments[ins_addr] = kb.comments[ins_addr]
        kb.sync.push_comments(comments)

        # stack_variables
        # TODO: update this kb usage after decompiler has an API
        code_view = self.workspace._get_or_create_pseudocode_view()
        var_manager = code_view.codegen._variable_kb.variables[func.addr]
        sim_vars = var_manager._unified_variables
        stack_vars = set(var for var in sim_vars if isinstance(var, SimStackVariable))
        kb.sync.push_stack_variables(stack_vars, var_manager)

        # TODO: Fix this
        kb.sync.commit()

    def pullFunction(self):
        func_view = self.workspace.view_manager.first_view_in_category('functions')

        user_action = func_view.sender()
        user = user_action.text()
        self._pull_func(user)

    def autoPullFunction(self):
        # TODO: implement auto-pulling
        return self.selected_func

    def pullPatches(self):
        func_view = self.workspace.view_manager.first_view_in_category('functions')

        user_action = func_view.sender()
        user = user_action.text()

        kb = self.workspace.instance.project.kb
        # currently we assume all patches are against the main object
        main_object = self.workspace.instance.project.loader.main_object
        patches = kb.sync.pull_patches(user=user)

        patch_added = False
        for patch in patches:
            addr = main_object.mapped_base + patch.offset
            kb.patches.add_patch(addr, patch.new_bytes)
            patch_added = True

        if patch_added:
            # trigger a refresh
            self.workspace.instance.patches.am_event()

            # re-generate the CFG
            # TODO: CFG refinement
            self.workspace.instance.generate_cfg()

    def _pull_func(self, user):
        current_function = self.selected_func

        disasm_view = self.workspace.view_manager.first_view_in_category("disassembly")
        code_view = self.workspace._get_or_create_pseudocode_view()
        func_table_view = self.workspace.view_manager.first_view_in_category("functions")

        # sync the function
        self.workspace.instance.project.kb.sync.fill_function(current_function, user=user)
        code_view.codegen.cfunc.name = self.workspace.instance.kb.functions[current_function.addr].name
        code_view.codegen.cfunc.demangled_name = code_view.codegen.cfunc.name

        # TODO move this into angr once we have a decompiler API
        # get stack variables and update internal kb
        var_manager = code_view.codegen._variable_kb.variables[current_function.addr]
        current_sim_vars = var_manager._unified_variables
        current_stack_vars = set(var for var in current_sim_vars if isinstance(var, SimStackVariable))
        stack_vars = self.workspace.instance.project.kb.sync.pull_stack_variables(current_function.addr, user=user)
        stack_var_dict = {s[0]: s[1] for s in stack_vars}
        for var in current_stack_vars:
            if isinstance(var, SimStackVariable):
                offset = var.offset
                try:
                    new_var = stack_var_dict[offset]
                except KeyError:
                    continue
                # overwrite the variable with the new var
                var.name = new_var.name

        # trigger a refresh
        disasm_view.refresh()
        code_view.refresh_text()
        func_table_view.refresh()
