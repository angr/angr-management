from PySide2.QtGui import QColor

COLOR_SCHEMES = {
    'Light': {
        'disasm_view_operand_color':                    QColor(0xf0, 0xf0, 0xf0),
        'disasm_view_variable_label_color':             QColor(0x00, 0x80, 0x00),
        'disasm_view_operand_highlight_color':          QColor(0xfc, 0xef, 0),
        'disasm_view_operand_select_color':             QColor(0xff, 0xff, 0),
        'disasm_view_function_color':                   QColor(200,  200,  200),
        'disasm_view_label_color':                      QColor(200,  200,  200),
        'disasm_view_label_highlight_color':            QColor(0xf0, 0xf0, 0xbf),
        'disasm_view_target_addr_color':                QColor(0,    0,    0xff),
        'disasm_view_antitarget_addr_color':            QColor(0xff, 0,    0),
        'disasm_view_node_shadow_color':                QColor(0,    0,    0,      75),
        'disasm_view_node_background_color':            QColor(60,   60,   60),
        'disasm_view_node_zoomed_out_background_color': QColor(100,  100,  100),
        'disasm_view_node_border_color':                QColor(80,   80,   80),
        'disasm_view_node_address_color':               QColor(0xe0, 0xe0, 0xe0),
        'disasm_view_node_mnemonic_color':              QColor(0xe0, 0xe0, 0xe0),
        'disasm_view_selected_node_border_color':       QColor(0x6b, 0x71, 0x7c),
        'disasm_view_printable_byte_color':             QColor(0,    0x80, 0x40),
        'disasm_view_printable_character_color':        QColor(0,    0x80, 0x40),
        'disasm_view_unprintable_byte_color':           QColor(0x80, 0x40, 0),
        'disasm_view_unprintable_character_color':      QColor(0x80, 0x40, 0),
        'disasm_view_unknown_byte_color':               QColor(0xf0, 0,    0),
        'disasm_view_unknown_character_color':          QColor(0xf0, 0,    0),
        'function_table_color':                         QColor(0xe0, 0xe0, 0xe0),
        'function_table_syscall_color':                 QColor(0,    0,    0x80),
        'function_table_plt_color':                     QColor(0,    0x80, 0),
        'function_table_simprocedure_color':            QColor(0x80, 0,    0),
        'function_table_alignment_color':               QColor(0x80, 0x80, 0),
        'palette_window':                               QColor(239, 239, 239, 255),
        'palette_windowtext':                           QColor(0, 0, 0, 255),
        'palette_base':                                 QColor(255, 255, 255, 255),
        'palette_alternatebase':                        QColor(247, 247, 247, 255),
        'palette_tooltipbase':                          QColor(255, 255, 220, 255),
        'palette_tooltiptext':                          QColor(0, 0, 0, 255),
        'palette_text':                                 QColor(0, 0, 0, 255),
        'palette_button':                               QColor(239, 239, 239, 255),
        'palette_buttontext':                           QColor(0, 0, 0, 255),
        'palette_brighttext':                           QColor(255, 255, 255, 255),
        'palette_highlight':                            QColor(48, 140, 198, 255),
        'palette_highlightedtext':                      QColor(255, 255, 255, 255),
        'palette_disabled_text':                        QColor(190, 190, 190, 255),
        'palette_disabled_buttontext':                  QColor(190, 190, 190, 255),
        'palette_disabled_windowtext':                  QColor(190, 190, 190, 255),
        'palette_light':                                QColor(255, 255, 255, 255),
        'palette_midlight':                             QColor(202, 202, 202, 255),
        'palette_dark':                                 QColor(159, 159, 159, 255),
        'palette_mid':                                  QColor(184, 184, 184, 255),
        'palette_shadow':                               QColor(118, 118, 118, 255),
        'palette_link':                                 QColor(0, 0, 255, 255),
        'palette_linkvisited':                          QColor(255, 0, 255, 255),

        # feature map
        'feature_map_color_regular_function': QColor(0,    0xa0, 0xe8),
        'feature_map_color_unknown':          QColor(0xa,  0xa,  0xa),
        'feature_map_color_delimiter':        QColor(0,    0,    0),
        'feature_map_color_data':             QColor(0xc0, 0xc0, 0xc0),
    },

    'Dark': {
        'disasm_view_operand_color':                    QColor(0xf0, 0xf0, 0xf0),
        'disasm_view_variable_label_color':             QColor(0x00, 0x80, 0x00),
        'disasm_view_operand_highlight_color':          QColor(0xfc, 0xef, 0),
        'disasm_view_operand_select_color':             QColor(0xff, 0xff, 0),
        'disasm_view_function_color':                   QColor(200,  200,  200),
        'disasm_view_label_color':                      QColor(200,  200,  200),
        'disasm_view_label_highlight_color':            QColor(0xf0, 0xf0, 0xbf),
        'disasm_view_target_addr_color':                QColor(0,    0,    0xff),
        'disasm_view_antitarget_addr_color':            QColor(0xff, 0,    0),
        'disasm_view_node_shadow_color':                QColor(0,    0,    0,      75),
        'disasm_view_node_background_color':            QColor(60,   60,   60),
        'disasm_view_node_zoomed_out_background_color': QColor(100,  100,  100),
        'disasm_view_node_border_color':                QColor(80,   80,   80),
        'disasm_view_node_address_color':               QColor(0xe0, 0xe0, 0xe0),
        'disasm_view_node_mnemonic_color':              QColor(0xe0, 0xe0, 0xe0),
        'disasm_view_selected_node_border_color':       QColor(0x6b, 0x71, 0x7c),
        'disasm_view_printable_byte_color':             QColor(0,    0x80, 0x40),
        'disasm_view_printable_character_color':        QColor(0,    0x80, 0x40),
        'disasm_view_unprintable_byte_color':           QColor(0x80, 0x40, 0),
        'disasm_view_unprintable_character_color':      QColor(0x80, 0x40, 0),
        'disasm_view_unknown_byte_color':               QColor(0xf0, 0,    0),
        'disasm_view_unknown_character_color':          QColor(0xf0, 0,    0),
        'function_table_color':                         QColor(0xe0, 0xe0, 0xe0),
        'function_table_syscall_color':                 QColor(0,    0,    0x80),
        'function_table_plt_color':                     QColor(0,    0x80, 0),
        'function_table_simprocedure_color':            QColor(0x80, 0,    0),
        'function_table_alignment_color':               QColor(0x80, 0x80, 0),
        'palette_window':                               QColor(0x35 ,0x35 ,0x35),
        'palette_windowtext':                           QColor(0xff, 0xff, 0xff),
        'palette_base':                                 QColor(0x28 ,0x28 ,0x28),
        'palette_alternatebase':                        QColor(0x35 ,0x35 ,0x35),
        'palette_tooltipbase':                          QColor(0x35 ,0x35 ,0x35),
        'palette_tooltiptext':                          QColor(0xff, 0xff, 0xff),
        'palette_text':                                 QColor(0xff, 0xff, 0xff),
        'palette_button':                               QColor(0x35 ,0x35 ,0x35),
        'palette_buttontext':                           QColor(0xff, 0xff, 0xff),
        'palette_brighttext':                           QColor(0xff, 0x00, 0x00),
        'palette_highlight':                            QColor(0x28 ,0x28 ,0x28).lighter(),
        'palette_highlightedtext':                      QColor(0xff, 0xff, 0xff),
        'palette_disabled_text':                        QColor(0x80, 0x80, 0x80),
        'palette_disabled_buttontext':                  QColor(0x80, 0x80, 0x80),
        'palette_disabled_windowtext':                  QColor(0x80, 0x80, 0x80),
        'palette_light':                                QColor(0,0,0),
        'palette_midlight':                             QColor(0,0,0),
        'palette_dark':                                 QColor(0,0,0),
        'palette_mid':                                  QColor(70,70,70),
        'palette_shadow':                               QColor(0,0,0),
        'palette_link':                                 QColor(45,197,45).lighter(),
        'palette_linkvisited':                          QColor(45,197,45).darker(),

        # feature map
        'feature_map_color_regular_function': QColor(0,    0xa0, 0xe8),
        'feature_map_color_unknown':          QColor(0xa,  0xa,  0xa),
        'feature_map_color_delimiter':        QColor(0,    0,    0),
        'feature_map_color_data':             QColor(0xc0, 0xc0, 0xc0),
    }
}
