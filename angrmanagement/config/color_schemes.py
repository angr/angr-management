from PySide6.QtGui import QColor


COLOR_SCHEMES = {
    "Light": {
        "disasm_view_operand_color": QColor(0x00, 0x00, 0x80),
        "disasm_view_operand_constant_color": QColor(0x00, 0x00, 0x80),
        "disasm_view_variable_label_color": QColor(0x00, 0x80, 0x00),
        "disasm_view_operand_highlight_color": QColor(0xFC, 0xEF, 0x00),
        "disasm_view_operand_select_color": QColor(0xFF, 0xFF, 0x00),
        "disasm_view_function_color": QColor(0x00, 0x00, 0xFF),
        "disasm_view_ir_default_color": QColor(0x80, 0x80, 0x80),
        "disasm_view_label_color": QColor(0x00, 0x00, 0xFF),
        "disasm_view_label_highlight_color": QColor(0xF0, 0xF0, 0xBF),
        "disasm_view_target_addr_color": QColor(0x00, 0x00, 0xFF),
        "disasm_view_antitarget_addr_color": QColor(0xFF, 0x00, 0x00),
        "disasm_view_node_shadow_color": QColor(0x00, 0x00, 0x00, 0x00),
        "disasm_view_node_background_color": QColor(0xFA, 0xFA, 0xFA),
        "disasm_view_node_zoomed_out_background_color": QColor(0xDA, 0xDA, 0xDA),
        "disasm_view_node_border_color": QColor(0xF0, 0xF0, 0xF0),
        "disasm_view_node_instruction_selected_background_color": QColor(0xB8, 0xC3, 0xD6),
        "disasm_view_node_address_color": QColor(0x00, 0x00, 0x00),
        "disasm_view_node_mnemonic_color": QColor(0x00, 0x00, 0x80),
        "disasm_view_selected_node_border_color": QColor(0x6B, 0x71, 0x7C),
        "disasm_view_printable_byte_color": QColor(0x00, 0x80, 0x40),
        "disasm_view_printable_character_color": QColor(0x00, 0x80, 0x40),
        "disasm_view_unprintable_byte_color": QColor(0x80, 0x40, 0x00),
        "disasm_view_unprintable_character_color": QColor(0x80, 0x40, 0x00),
        "disasm_view_unknown_byte_color": QColor(0xF0, 0x00, 0x00),
        "disasm_view_unknown_character_color": QColor(0xF0, 0x00, 0x00),
        "disasm_view_back_edge_color": QColor(0xF9, 0xD5, 0x77),
        "disasm_view_true_edge_color": QColor(0x79, 0xCC, 0xCD),
        "disasm_view_false_edge_color": QColor(0xF1, 0x66, 0x64),
        "disasm_view_direct_jump_edge_color": QColor(0x56, 0x5A, 0x5C),
        "disasm_view_exception_edge_color": QColor(0xF9, 0x91, 0x0A),
        "hex_view_selection_color": QColor(0xFF, 0x00, 0x00),
        "hex_view_selection_alt_color": QColor(0xA0, 0xA0, 0xA4),
        "hex_view_data_color": QColor(0x00, 0x00, 0xFF),
        "hex_view_string_color": QColor(0x00, 0xFF, 0xFF),
        "hex_view_instruction_color": QColor(0xFF, 0x00, 0xFF),
        "function_table_color": QColor(0x00, 0x00, 0x00),
        "function_table_syscall_color": QColor(0x00, 0x00, 0x80),
        "function_table_plt_color": QColor(0x00, 0x80, 0x00),
        "function_table_simprocedure_color": QColor(0x80, 0x00, 0x00),
        "function_table_alignment_color": QColor(0x80, 0x00, 0x80),
        "function_table_signature_bg_color": QColor(0xAA, 0xFF, 0xFF),
        "palette_window": QColor(0xEF, 0xEF, 0xEF, 0xFF),
        "palette_windowtext": QColor(0x00, 0x00, 0x00, 0xFF),
        "palette_base": QColor(0xFF, 0xFF, 0xFF, 0xFF),
        "palette_alternatebase": QColor(0xF7, 0xF7, 0xF7, 0xFF),
        "palette_tooltipbase": QColor(0xFF, 0xFF, 0xDC, 0xFF),
        "palette_tooltiptext": QColor(0x00, 0x00, 0x00, 0xFF),
        "palette_text": QColor(0x00, 0x00, 0x00, 0xFF),
        "palette_button": QColor(0xEF, 0xEF, 0xEF, 0xFF),
        "palette_buttontext": QColor(0x00, 0x00, 0x00, 0xFF),
        "palette_brighttext": QColor(0xFF, 0xFF, 0xFF, 0xFF),
        "palette_highlight": QColor(0x30, 0x8C, 0xC6, 0xFF),
        "palette_highlightedtext": QColor(0xFF, 0xFF, 0xFF, 0xFF),
        "palette_disabled_text": QColor(0xBE, 0xBE, 0xBE, 0xFF),
        "palette_disabled_buttontext": QColor(0xBE, 0xBE, 0xBE, 0xFF),
        "palette_disabled_windowtext": QColor(0xBE, 0xBE, 0xBE, 0xFF),
        "palette_light": QColor(0xDF, 0xDF, 0xDF, 0xDF),
        "palette_midlight": QColor(0xCA, 0xCA, 0xCA, 0xFF),
        "palette_dark": QColor(0x9F, 0x9F, 0x9F, 0xFF),
        "palette_mid": QColor(0xB8, 0xB8, 0xB8, 0xFF),
        "palette_shadow": QColor(0x76, 0x76, 0x76, 0xFF),
        "palette_link": QColor(0x00, 0x00, 0xFF, 0xFF),
        "palette_linkvisited": QColor(0xFF, 0x00, 0xFF, 0xFF),
        "feature_map_color_regular_function": QColor(0x00, 0xA0, 0xE8),
        "feature_map_color_unknown": QColor(0x0A, 0x0A, 0x0A),
        "feature_map_color_delimiter": QColor(0x00, 0x00, 0x00),
        "feature_map_color_data": QColor(0xC0, 0xC0, 0xC0),
        "pseudocode_comment_color": QColor(0x00, 0x80, 0x00, 0xFF),
        "pseudocode_function_color": QColor(0x00, 0x00, 0xFF, 0xFF),
        "pseudocode_quotation_color": QColor(0x00, 0x80, 0x00, 0xFF),
        "pseudocode_keyword_color": QColor(0x00, 0x00, 0x80, 0xFF),
        "pseudocode_highlight_color": QColor(0xFF, 0xFF, 0x00, 0xFF),
        "proximity_node_background_color": QColor(0xFA, 0xFA, 0xFA),
        "proximity_node_selected_background_color": QColor(0xCC, 0xCC, 0xCC),
        "proximity_node_border_color": QColor(0xF0, 0xF0, 0xF0),
        "proximity_function_node_text_color": QColor(0xFF, 0x00, 0x00),
        "proximity_string_node_text_color": QColor(0x00, 0x80, 0x00),
        "proximity_integer_node_text_color": QColor(0x00, 0x00, 0x80),
        "proximity_variable_node_text_color": QColor(0x00, 0x00, 0x80),
        "proximity_unknown_node_text_color": QColor(0x00, 0x00, 0x80),
        "proximity_call_node_text_color": QColor(0x00, 0x00, 0xFF),
        "proximity_call_node_text_color_plt": QColor(0x8B, 0x00, 0x8B),
        "proximity_call_node_text_color_simproc": QColor(0x8B, 0x00, 0x8B),
    },
    "Dark": {
        "disasm_view_operand_color": QColor(0xF0, 0xF0, 0x5A),
        "disasm_view_operand_constant_color": QColor(0x34, 0xF0, 0x8C),
        "disasm_view_variable_label_color": QColor(0x34, 0xD4, 0xF0),
        "disasm_view_operand_highlight_color": QColor(0x05, 0x2F, 0x50),
        "disasm_view_operand_select_color": QColor(0x09, 0x50, 0x8D),
        "disasm_view_function_color": QColor(0xC8, 0xC8, 0xC8),
        "disasm_view_ir_default_color": QColor(0x80, 0x80, 0x80),
        "disasm_view_label_color": QColor(0x00, 0xAA, 0xFF),
        "disasm_view_label_highlight_color": QColor(0x2F, 0x2F, 0x25),
        "disasm_view_target_addr_color": QColor(0x00, 0xAA, 0xFF),
        "disasm_view_antitarget_addr_color": QColor(0xFF, 0x00, 0x00),
        "disasm_view_node_shadow_color": QColor(0x00, 0x00, 0x00, 0x4B),
        "disasm_view_node_background_color": QColor(0x3C, 0x3C, 0x3C),
        "disasm_view_node_zoomed_out_background_color": QColor(0x64, 0x64, 0x64),
        "disasm_view_node_border_color": QColor(0x50, 0x50, 0x50),
        "disasm_view_node_instruction_selected_background_color": QColor(0x4C, 0x50, 0x58),
        "disasm_view_node_address_color": QColor(0x2C, 0xC9, 0x76),
        "disasm_view_node_mnemonic_color": QColor(0xE0, 0xE0, 0xE0),
        "disasm_view_selected_node_border_color": QColor(0x6B, 0x71, 0x7C),
        "disasm_view_printable_byte_color": QColor(0x00, 0x80, 0x40),
        "disasm_view_printable_character_color": QColor(0x00, 0x80, 0x40),
        "disasm_view_unprintable_byte_color": QColor(0xBA, 0xBA, 0xBA),
        "disasm_view_unprintable_character_color": QColor(0xBA, 0xBA, 0xBA),
        "disasm_view_unknown_byte_color": QColor(0xF0, 0x00, 0x00),
        "disasm_view_unknown_character_color": QColor(0xF0, 0x00, 0x00),
        "disasm_view_back_edge_color": QColor(0xF9, 0xD5, 0x77),
        "disasm_view_true_edge_color": QColor(0x79, 0xCC, 0xCD),
        "disasm_view_false_edge_color": QColor(0xF1, 0x66, 0x64),
        "disasm_view_direct_jump_edge_color": QColor(0x56, 0x5A, 0x5C),
        "disasm_view_exception_edge_color": QColor(0xF9, 0x91, 0x0A),
        "hex_view_selection_color": QColor(0xFF, 0x00, 0x00),
        "hex_view_selection_alt_color": QColor(0xA0, 0xA0, 0xA4),
        "hex_view_data_color": QColor(0x00, 0x00, 0xFF),
        "hex_view_string_color": QColor(0x00, 0xFF, 0xFF),
        "hex_view_instruction_color": QColor(0xFF, 0x00, 0xFF),
        "function_table_color": QColor(0xE0, 0xE0, 0xE0),
        "function_table_syscall_color": QColor(0x00, 0x00, 0x80),
        "function_table_plt_color": QColor(0x00, 0x80, 0x00),
        "function_table_simprocedure_color": QColor(0x80, 0x00, 0x00),
        "function_table_alignment_color": QColor(0x80, 0x80, 0x00),
        "function_table_signature_bg_color": QColor(0xAA, 0xFF, 0xFF),
        "palette_window": QColor(0x35, 0x35, 0x35),
        "palette_windowtext": QColor(0xFF, 0xFF, 0xFF),
        "palette_base": QColor(0x28, 0x28, 0x28),
        "palette_alternatebase": QColor(0x1D, 0x1D, 0x1D),
        "palette_tooltipbase": QColor(0x35, 0x35, 0x35),
        "palette_tooltiptext": QColor(0xFF, 0xFF, 0xFF),
        "palette_text": QColor(0xE0, 0xE0, 0xE0),
        "palette_button": QColor(0x35, 0x35, 0x35),
        "palette_buttontext": QColor(0xE0, 0xE0, 0xE0),
        "palette_brighttext": QColor(0xFF, 0x00, 0x00),
        "palette_highlight": QColor(0x46, 0x85, 0xE5),
        "palette_highlightedtext": QColor(0xFF, 0xFF, 0xFF),
        "palette_disabled_text": QColor(0x80, 0x80, 0x80),
        "palette_disabled_buttontext": QColor(0x80, 0x80, 0x80),
        "palette_disabled_windowtext": QColor(0x80, 0x80, 0x80),
        "palette_light": QColor(0x46, 0x46, 0x46),
        "palette_midlight": QColor(0x40, 0x40, 0x40),
        "palette_dark": QColor(0x20, 0x20, 0x20),
        "palette_mid": QColor(0x28, 0x28, 0x28),
        "palette_shadow": QColor(0x16, 0x16, 0x16),
        "palette_link": QColor(0x2D, 0xC5, 0x2D).lighter(),
        "palette_linkvisited": QColor(0x2D, 0xC5, 0x2D).darker(),
        "feature_map_color_regular_function": QColor(0x00, 0xA0, 0xE8),
        "feature_map_color_unknown": QColor(0x0A, 0x0A, 0x0A),
        "feature_map_color_delimiter": QColor(0x00, 0x00, 0x00),
        "feature_map_color_data": QColor(0xC0, 0xC0, 0xC0),
        "pseudocode_comment_color": QColor(0x00, 0x80, 0x00, 0xFF),
        "pseudocode_function_color": QColor(0x60, 0x80, 0xFF, 0xFF),
        "pseudocode_quotation_color": QColor(0x00, 0x80, 0x00, 0xFF),
        "pseudocode_keyword_color": QColor(0x00, 0xFF, 0xFF, 0xFF),
        "pseudocode_highlight_color": QColor(0x59, 0x44, 0x05, 0xFF),
        "proximity_node_background_color": QColor(0x3C, 0x3C, 0x3C),
        "proximity_node_selected_background_color": QColor(0x4C, 0x50, 0x58),
        "proximity_node_border_color": QColor(0x50, 0x50, 0x50),
        "proximity_function_node_text_color": QColor(0xFF, 0x00, 0xFF),
        "proximity_string_node_text_color": QColor(0xFA, 0xFA, 0xFA),
        "proximity_integer_node_text_color": QColor(0xFA, 0xFA, 0xFA),
        "proximity_variable_node_text_color": QColor(0xFA, 0xFA, 0xFA),
        "proximity_unknown_node_text_color": QColor(0xFA, 0xFA, 0xFA),
        "proximity_call_node_text_color": QColor(0x34, 0xD4, 0xF0),
        "proximity_call_node_text_color_plt": QColor(0x2C, 0xC9, 0x76),
        "proximity_call_node_text_color_simproc": QColor(0x2C, 0xC9, 0x76),
    },
}
