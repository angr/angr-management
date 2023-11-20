from PySide6.QtGui import QColor, QFont

COLOR_SCHEMES = {
    "Light": {
        "disasm_view_minimap_background_color": QColor(0xFF, 0xFF, 0xFF, 0xFF),
        "disasm_view_minimap_outline_color": QColor(0xB8, 0xB8, 0xB8, 0xFF),
        "disasm_view_operand_color": QColor(0x00, 0x00, 0x80),
        "disasm_view_operand_constant_color": QColor(0x10, 0x78, 0x96),
        "disasm_view_variable_label_color": QColor(0x00, 0x80, 0x00),
        "disasm_view_background_color": QColor(0xFF, 0xFF, 0xFF, 0xFF),
        "disasm_view_operand_highlight_color": QColor(0xFC, 0xEF, 0x00),
        "disasm_view_operand_select_color": QColor(0xFF, 0xFF, 0x00),
        "disasm_view_function_color": QColor(0x00, 0x00, 0xFF),
        "disasm_view_string_color": QColor(0xA0, 0xA0, 0xA4),
        "disasm_view_comment_color": QColor(0x37, 0x3D, 0x3F),
        "disasm_view_variable_ident_color": QColor(0xAA, 0x25, 0xDA),
        "disasm_view_variable_offset_color": QColor(0x80, 0x80, 0x00),
        "disasm_view_branch_target_text_color": QColor(0x80, 0x80, 0x00),
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
        "palette_placeholdertext": QColor(0x00, 0x00, 0x00, 0xAF),
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
        "feature_map_regular_function_color": QColor(0x00, 0xA0, 0xE8),
        "feature_map_unknown_color": QColor(0x0A, 0x0A, 0x0A),
        "feature_map_delimiter_color": QColor(0x00, 0x00, 0x00),
        "feature_map_data_color": QColor(0xC0, 0xC0, 0xC0),
        "feature_map_string_color": QColor(0x00, 0xF0, 0x80),
        "pseudocode_comment_color": QColor(0x00, 0x80, 0x00, 0xFF),
        "pseudocode_function_color": QColor(0x00, 0x00, 0xFF, 0xFF),
        "pseudocode_library_function_color": QColor(0xFF, 0x00, 0xFF),
        "pseudocode_quotation_color": QColor(0x00, 0x80, 0x00, 0xFF),
        "pseudocode_keyword_color": QColor(0x00, 0x00, 0x80, 0xFF),
        "pseudocode_types_color": QColor(0x10, 0x78, 0x96),
        "pseudocode_variable_color": QColor(0x00, 0x00, 0x00, 0xFF),
        "pseudocode_label_color": QColor(0x00, 0x00, 0xFF),
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
        "disasm_view_minimap_background_color": QColor(0x28, 0x28, 0x28),
        "disasm_view_minimap_outline_color": QColor(0x40, 0x40, 0x40),
        "disasm_view_operand_color": QColor(0xF0, 0xF0, 0x5A),
        "disasm_view_operand_constant_color": QColor(0x34, 0xF0, 0x8C),
        "disasm_view_background_color": QColor(0x28, 0x28, 0x28),
        "disasm_view_variable_label_color": QColor(0x34, 0xD4, 0xF0),
        "disasm_view_operand_highlight_color": QColor(0x05, 0x2F, 0x50),
        "disasm_view_operand_select_color": QColor(0x09, 0x50, 0x8D),
        "disasm_view_function_color": QColor(0xC8, 0xC8, 0xC8),
        "disasm_view_string_color": QColor(0xA0, 0xA0, 0xA4),
        "disasm_view_comment_color": QColor(0xF5, 0xC2, 0x42, 0xBB),
        "disasm_view_variable_ident_color": QColor(0xF1, 0xA7, 0xFA),
        "disasm_view_variable_offset_color": QColor(0x80, 0x80, 0x00),
        "disasm_view_branch_target_text_color": QColor(0x80, 0x80, 0x00),
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
        "palette_placeholdertext": QColor(0xF8, 0xF8, 0xF8, 0xBB),
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
        "feature_map_regular_function_color": QColor(0x00, 0xA0, 0xE8),
        "feature_map_unknown_color": QColor(0x0A, 0x0A, 0x0A),
        "feature_map_delimiter_color": QColor(0x00, 0x00, 0x00),
        "feature_map_data_color": QColor(0xC0, 0xC0, 0xC0),
        "feature_map_string_color": QColor(0x00, 0xF0, 0x80),
        "pseudocode_comment_color": QColor(0x00, 0x80, 0x00, 0xFF),
        "pseudocode_function_color": QColor(0x00, 0xAA, 0xFF),
        "pseudocode_library_function_color": QColor(0xAA, 0x00, 0xFF),
        "pseudocode_quotation_color": QColor(0x00, 0x80, 0x00, 0xFF),
        "pseudocode_keyword_color": QColor(0xF1, 0xA7, 0xFA),
        "pseudocode_types_color": QColor(0x00, 0xFF, 0xFF, 0xFF),
        "pseudocode_variable_color": QColor(0xE0, 0xE0, 0xE0),
        "pseudocode_label_color": QColor(0x00, 0xAA, 0xFF),
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
    "Dracula": {
        "disasm_view_minimap_background_color": QColor(0x28, 0x2A, 0x36),
        "disasm_view_minimap_viewport_color": QColor(0x44, 0x47, 0x5A),
        "disasm_view_minimap_outline_color": QColor(0x44, 0x47, 0x5A),
        "disasm_view_operand_color": QColor(0xFF, 0x79, 0xC6),
        "disasm_view_operand_constant_color": QColor(0xF1, 0xFA, 0x8C),
        "disasm_view_background_color": QColor(0x1C, 0x1D, 0x26),
        "disasm_view_variable_label_color": QColor(0x34, 0xD4, 0xF0),
        "disasm_view_operand_highlight_color": QColor(0x05, 0x2F, 0x50),
        "disasm_view_operand_select_color": QColor(0x09, 0x50, 0x8D),
        "disasm_view_function_color": QColor(0xF8, 0xF8, 0xF2),
        "disasm_view_string_color": QColor(0xFF, 0xB8, 0x6C),
        "disasm_view_comment_color": QColor(0x5B, 0x65, 0x8E),
        "disasm_view_variable_ident_color": QColor(0xBD, 0x93, 0xF9),
        "disasm_view_ir_default_color": QColor(0x50, 0xFA, 0x7B),
        "disasm_view_label_color": QColor(0x00, 0xAA, 0xFF),
        "disasm_view_label_highlight_color": QColor(0x2F, 0x2F, 0x25),
        "disasm_view_target_addr_color": QColor(0x50, 0xFA, 0x7B),
        "disasm_view_antitarget_addr_color": QColor(0xFF, 0x6E, 0x6E),
        "disasm_view_node_shadow_color": QColor(0x00, 0x00, 0x00),
        "disasm_view_node_background_color": QColor(0x28, 0x2A, 0x36),
        "disasm_view_node_zoomed_out_background_color": QColor(0x5D, 0x62, 0x7E),
        "disasm_view_node_border_color": QColor(0x50, 0x50, 0x50),
        "disasm_view_node_instruction_selected_background_color": QColor(0x44, 0x47, 0x5A),
        "disasm_view_node_address_color": QColor(0x3F, 0xA1, 0x5D),
        "disasm_view_node_mnemonic_color": QColor(0xF8, 0xF8, 0xF2),
        "disasm_view_selected_node_border_color": QColor(0x6B, 0x71, 0x7C),
        "disasm_view_printable_byte_color": QColor(0x50, 0xFA, 0x7B),
        "disasm_view_printable_character_color": QColor(0x50, 0xFA, 0x7B),
        "disasm_view_unprintable_byte_color": QColor(0xBA, 0xBA, 0xBA),
        "disasm_view_unprintable_character_color": QColor(0xBA, 0xBA, 0xBA),
        "disasm_view_unknown_byte_color": QColor(0xFF, 0x6E, 0x6E),
        "disasm_view_unknown_character_color": QColor(0xFF, 0x6E, 0x6E),
        "disasm_view_back_edge_color": QColor(0x9B, 0xA1, 0x67),
        "disasm_view_true_edge_color": QColor(0x3F, 0xA1, 0x5D),
        "disasm_view_false_edge_color": QColor(0xA3, 0x43, 0x48),
        "disasm_view_direct_jump_edge_color": QColor(0x56, 0x5A, 0x5C),
        "disasm_view_exception_edge_color": QColor(0xFF, 0xB8, 0x6C),
        "hex_view_selection_color": QColor(0x44, 0x47, 0x5A),
        "hex_view_selection_alt_color": QColor(0x9B, 0x9E, 0xB3),
        "hex_view_data_color": QColor(0x61, 0x97, 0xA8),
        "hex_view_string_color": QColor(0x9B, 0xA1, 0x67),
        "hex_view_instruction_color": QColor(0xA3, 0x57, 0x88),
        "function_table_color": QColor(0xF8, 0xF8, 0xF2),
        "function_table_syscall_color": QColor(0x00, 0x00, 0x80),
        "function_table_plt_color": QColor(0x50, 0xFA, 0x7B),
        "function_table_simprocedure_color": QColor(0xFF, 0x55, 0x55),
        "function_table_alignment_color": QColor(0xF1, 0xFA, 0x8C),
        "function_table_signature_bg_color": QColor(0x8B, 0xE9, 0xFD),
        "palette_window": QColor(0x24, 0x26, 0x31),
        "palette_windowtext": QColor(0xF8, 0xF8, 0xF2),
        "palette_base": QColor(0x28, 0x2A, 0x36),
        "palette_alternatebase": QColor(0x3A, 0x3D, 0x4E),
        "palette_tooltipbase": QColor(0x24, 0x26, 0x31),
        "palette_tooltiptext": QColor(0xF8, 0xF8, 0xF2),
        "palette_placeholdertext": QColor(0xF8, 0xF8, 0xF2, 0xBB),
        "palette_text": QColor(0xF8, 0xF8, 0xF2),
        "palette_button": QColor(0x24, 0x26, 0x31),
        "palette_buttontext": QColor(0xF8, 0xF8, 0xF2),
        "palette_brighttext": QColor(0xFF, 0xFF, 0xFF),
        "palette_highlight": QColor(0x44, 0x47, 0x5A),
        "palette_highlightedtext": QColor(0xF8, 0xF8, 0xF2),
        "palette_disabled_text": QColor(0x80, 0x80, 0x80),
        "palette_disabled_buttontext": QColor(0x80, 0x80, 0x80),
        "palette_disabled_windowtext": QColor(0x80, 0x80, 0x80),
        "palette_light": QColor(0x41, 0x44, 0x57),
        "palette_midlight": QColor(0x3B, 0x3E, 0x50),
        "palette_dark": QColor(0x1C, 0x1D, 0x26),
        "palette_mid": QColor(0x28, 0x2A, 0x36),
        "palette_shadow": QColor(0x16, 0x17, 0x1E),
        "palette_link": QColor(0x8B, 0xE9, 0xFD),
        "palette_linkvisited": QColor(0xBD, 0x93, 0xF9),
        "pseudocode_comment_color": QColor(0x62, 0x72, 0xA4),
        "pseudocode_comment_weight": QFont.Weight.Normal,
        "pseudocode_function_color": QColor(0x50, 0xFA, 0x7B),
        "pseudocode_library_function_color": QColor(0x8B, 0xE9, 0xFD),
        "pseudocode_quotation_color": QColor(0xF1, 0xFA, 0x8C),
        "pseudocode_keyword_color": QColor(0xFF, 0x79, 0xC6),
        "pseudocode_types_color": QColor(0x8B, 0xE9, 0xFD),
        "pseudocode_types_style": QFont.Style.StyleItalic,
        "pseudocode_variable_color": QColor(0xF8, 0xF8, 0xF2),
        "pseudocode_label_color": QColor(0x00, 0xAA, 0xFF),
        "pseudocode_highlight_color": QColor(0x44, 0x47, 0x5A),
        "proximity_node_background_color": QColor(0x28, 0x2A, 0x36),
        "proximity_node_selected_background_color": QColor(0x4C, 0x50, 0x58),
        "proximity_node_border_color": QColor(0x50, 0x50, 0x50),
        "proximity_function_node_text_color": QColor(0xF8, 0xF8, 0xF2),
        "proximity_string_node_text_color": QColor(0xF1, 0xFA, 0x8C),
        "proximity_integer_node_text_color": QColor(0xF1, 0xFA, 0x8C),
        "proximity_variable_node_text_color": QColor(0xFF, 0x79, 0xC6),
        "proximity_unknown_node_text_color": QColor(0xF8, 0xF8, 0xF2),
        "proximity_call_node_text_color": QColor(0x34, 0xD4, 0xF0),
        "proximity_call_node_text_color_plt": QColor(0x50, 0xFA, 0x7B),
        "proximity_call_node_text_color_simproc": QColor(0xFF, 0x55, 0x55),
        "feature_map_regular_function_color": QColor(0x50, 0xFA, 0x7B),
        "feature_map_unknown_color": QColor(0x28, 0x2A, 0x36),
        "feature_map_delimiter_color": QColor(0x00, 0x00, 0x00),
        "feature_map_data_color": QColor(0x5D, 0x62, 0x7E),
        "feature_map_string_color": QColor(0xF1, 0xFA, 0x8C),
    },
    "Catppuccin Mocha": {
        # Disassembly View Colors
        "disasm_view_minimap_background_color": QColor(30, 30, 46),  # base
        "disasm_view_minimap_outline_color": QColor(88, 91, 112),  # surface2
        "disasm_view_operand_color": QColor(137, 220, 235),  # sky
        "disasm_view_operand_constant_color": QColor(249, 226, 175),  # yellow
        "disasm_view_variable_label_color": QColor(166, 227, 161),  # green
        "disasm_view_background_color": QColor(30, 30, 46),  # base
        "disasm_view_function_color": QColor(166, 227, 161),  # green
        "disasm_view_string_color": QColor(249, 226, 175),  # yellow
        "disasm_view_comment_color": QColor(205, 214, 244),  # text
        "disasm_view_variable_ident_color": QColor(180, 190, 254),  # lavender
        "disasm_view_variable_offset_color": QColor(243, 139, 168),  # red
        "disasm_view_branch_target_text_color": QColor(137, 180, 250),  # blue
        "disasm_view_ir_default_color": QColor(88, 91, 112),  # surface2
        "disasm_view_label_color": QColor(137, 220, 235),  # sky
        "disasm_view_label_highlight_color": QColor(105, 110, 150),
        "disasm_view_target_addr_color": QColor(166, 227, 161),  # green
        "disasm_view_antitarget_addr_color": QColor(243, 139, 168),  # red
        "disasm_view_node_shadow_color": QColor(0, 0, 0, 0),  # transparent
        "disasm_view_node_background_color": QColor(30, 30, 46),  # base
        "disasm_view_node_zoomed_out_background_color": QColor(49, 50, 68),  # surface0
        "disasm_view_node_border_color": QColor(49, 50, 68),  # surface0
        "disasm_view_node_address_color": QColor(205, 214, 244),  # text
        "disasm_view_node_mnemonic_color": QColor(137, 220, 235),  # sky
        "disasm_view_printable_byte_color": QColor(166, 227, 161),  # green
        "disasm_view_printable_character_color": QColor(166, 227, 161),  # green
        "disasm_view_unprintable_byte_color": QColor(243, 139, 168),  # red
        "disasm_view_unprintable_character_color": QColor(243, 139, 168),  # red
        "disasm_view_unknown_byte_color": QColor(137, 220, 235),  # sky
        "disasm_view_unknown_character_color": QColor(137, 220, 235),  # sky
        "disasm_view_back_edge_color": QColor(166, 227, 161),  # green
        "disasm_view_true_edge_color": QColor(166, 227, 161),  # green
        "disasm_view_false_edge_color": QColor(243, 139, 168),  # red
        "disasm_view_direct_jump_edge_color": QColor(137, 220, 235),  # sky
        "disasm_view_exception_edge_color": QColor(243, 139, 168),  # red
        # Hex View Colors
        "hex_view_selection_color": QColor(105, 110, 150),  # Custom highlight
        "hex_view_selection_alt_color": QColor(105, 110, 150),  # Custom highlight
        "hex_view_data_color": QColor(137, 180, 250),  # blue
        "hex_view_string_color": QColor(249, 226, 175),  # yellow
        "hex_view_instruction_color": QColor(166, 227, 161),  # green
        # Function Table Colors
        "function_table_color": QColor(205, 214, 244),  # text
        "function_table_syscall_color": QColor(243, 139, 168),  # red
        "function_table_plt_color": QColor(166, 227, 161),  # green
        "function_table_simprocedure_color": QColor(180, 190, 254),  # lavender
        "function_table_alignment_color": QColor(249, 226, 175),  # yellow
        "function_table_signature_bg_color": QColor(245, 224, 220),  # rosewater
        # Palette Colors
        "palette_window": QColor(30, 30, 46),  # base
        "palette_windowtext": QColor(205, 214, 244),  # text
        "palette_base": QColor(30, 30, 46),  # base
        "palette_alternatebase": QColor(49, 50, 68),  # surface0
        "palette_tooltipbase": QColor(30, 30, 46),  # base
        "palette_tooltiptext": QColor(88, 91, 112),  # surface2
        "palette_text": QColor(205, 214, 244),  # text
        "palette_button": QColor(30, 30, 46),  # base
        "palette_buttontext": QColor(88, 91, 112),  # surface2
        "palette_brighttext": QColor(88, 91, 112),  # surface2
        "palette_highlight": QColor(105, 110, 150),  # Custom highlight
        "palette_highlightedtext": QColor(255, 255, 255),  # White text for contrast
        # Feature Map Colors
        "feature_map_regular_function_color": QColor(166, 227, 161),  # green
        "feature_map_unknown_color": QColor(137, 220, 235),  # sky
        "feature_map_delimiter_color": QColor(249, 226, 175),  # yellow
        "feature_map_data_color": QColor(180, 190, 254),  # lavender
        "feature_map_string_color": QColor(249, 226, 175),  # yellow
        # Pseudocode Colors
        "pseudocode_comment_color": QColor(205, 214, 244),  # text
        "pseudocode_function_color": QColor(166, 227, 161),  # green
        "pseudocode_library_function_color": QColor(243, 139, 168),  # red
        "pseudocode_quotation_color": QColor(166, 227, 161),  # green
        "pseudocode_keyword_color": QColor(137, 220, 235),  # sky
        "pseudocode_types_color": QColor(249, 226, 175),  # yellow
        "pseudocode_variable_color": QColor(205, 214, 244),  # text
        "pseudocode_label_color": QColor(137, 220, 235),  # sky
        "pseudocode_highlight_color": QColor(105, 110, 150),  # Custom highlight
        # Proximity View Colors
        "proximity_node_background_color": QColor(30, 30, 46),  # base
        "proximity_node_selected_background_color": QColor(105, 110, 150),  # Custom highlight
        "proximity_node_border_color": QColor(88, 91, 112),  # surface2
        "proximity_function_node_text_color": QColor(166, 227, 161),  # green
        "proximity_string_node_text_color": QColor(249, 226, 175),  # yellow
        "proximity_integer_node_text_color": QColor(137, 220, 235),  # sky
        "proximity_variable_node_text_color": QColor(180, 190, 254),  # lavender
        "proximity_unknown_node_text_color": QColor(245, 224, 220),  # rosewater
        "proximity_call_node_text_color": QColor(166, 227, 161),  # green
        "proximity_call_node_text_color_plt": QColor(137, 180, 250),  # blue
        "proximity_call_node_text_color_simproc": QColor(243, 139, 168),  # red
        # Palette Colors
        "palette_mid": QColor(68, 71, 90),  # A mid-tone color between surface0 and base
        "palette_placeholdertext": QColor(137, 220, 235, 128),  # Sky color with 50% opacity for placeholder text
        "palette_light": QColor(68, 71, 90),  # Lighter than base but not too bright
        "palette_midlight": QColor(58, 60, 78),  # A slightly lighter surface color for a subtle lift
        "palette_dark": QColor(20, 20, 30),  # A darker version of the base for depth
        "palette_shadow": QColor(0, 0, 0, 50),  # A soft shadow with 50% opacity
        "palette_link": QColor(137, 220, 235),  # Sky color for links
        "palette_linkvisited": QColor(180, 190, 254),  # Lavender color to indicate visited links
        # Disabled Colors
        "palette_disabled_text": QColor(88, 91, 112, 128),  # Surface2 color with 50% opacity for disabled text
        "palette_disabled_buttontext": QColor(
            88, 91, 112, 128
        ),  # Surface2 color with 50% opacity for disabled button text
        "palette_disabled_windowtext": QColor(
            88, 91, 112, 128
        ),  # Surface2 color with 50% opacity for disabled window text
        # Disassembly View Colors
        "disasm_view_node_instruction_selected_background_color": QColor(
            105, 110, 150
        ),  # Custom highlight for selected instruction background
        "disasm_view_operand_highlight_color": QColor(
            105, 110, 150, 128
        ),  # Custom highlight with 50% opacity for operand highlight
        "disasm_view_selected_node_border_color": QColor(105, 110, 150),  # Custom highlight for selected node border
        "disasm_view_operand_select_color": QColor(105, 110, 150),  # Custom highlight for operand selection
    },
}
