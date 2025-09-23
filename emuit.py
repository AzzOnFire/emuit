import sys

import idaapi
import ida_kernwin
import idautils

from emuit import EmuItIda, IdaUiUtils, IdaCommentUtils 


ida_version = tuple(map(int, idaapi.get_kernel_version().split(".")))
assert (ida_version >= (8, 3)), "ERROR: EmuIt requires IDA 8.3+"
assert (sys.version_info >= (3, 8)), "ERROR: EmuIt requires Python 3.8"


PLUGIN_NAME = 'EmuIt'
VERSION = '0.8.0'
PLUGIN_HOTKEY = 'Shift+C'

ACTION_RUN = 'EmuIt:run'
ACTION_RESET = 'EmuIt:reset'
ACTION_EMULATE_CALLS = 'EmuIt:emulate_calls'
ACTION_TOGGLE_RESET = 'EmuIt:toggle_reset'
ACTION_TOGGLE_UNWIND = 'EmuIt:toggle_unwind'
ACTION_TOGGLE_COMMENTS = 'EmuIt:toggle_beutify'


class EmuItPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = 'Easy-to-use code emulator'
    help = ''
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ''

    def banner(self):
        print('=' * 52, '\n', ' ' * 52)
        print(r'  ______     __    __     __  __     __     ______  ')
        print(r' /\  ___\   /\ "-./  \   /\ \/\ \   /\ \   /\__  _\ ')
        print(r' \ \  __\   \ \ \-./\ \  \ \ \_\ \  \ \ \  \/_/\ \/ ')
        print(r'  \ \_____\  \ \_\ \ \_\  \ \_____\  \ \_\    \ \_\ ')
        print(r'   \/_____/   \/_/  \/_/   \/_____/   \/_/     \/_/ ')
        print(' ' * 52, '\n', '=' * 52)

    def init(self):
        #try:
        self.emu = EmuItIda()
        #except Exception as e:
        #    print('EmuIt: an error occurred during initialization:', str(e))
        #    return idaapi.PLUGIN_SKIP

        self.reset_every_run = True
        self.show_comments = True

        action_run = idaapi.action_desc_t(
            ACTION_RUN,
            'Run',
            action_handler(self.action_run_handler),
            PLUGIN_HOTKEY,
            'Run EmuIt on selection'
        )

        action_reset = idaapi.action_desc_t(
            ACTION_RESET,
            'Reset state',
            action_handler(self.action_reset_handler),
            None,
            'Reset EmuIt state now'
        )

        action_toggle_reset = idaapi.action_desc_t(
            ACTION_TOGGLE_RESET,
            'Reset on every run',
            action_handler(self.action_toggle_reset_handler),
            None,
            'Reset EmuIt state on every run'
        )

        action_toggle_unwind = idaapi.action_desc_t(
            ACTION_TOGGLE_UNWIND,
            'Unwind on error',
            action_handler(self.action_toggle_unwind_handler),
            None,
            None,
        )

        action_toggle_comments = idaapi.action_desc_t(
            ACTION_TOGGLE_COMMENTS,
            'Show comments',
            action_handler(self.action_toggle_comments_handler),
            None,
            None,
        )

        action_calls = idaapi.action_desc_t(
            ACTION_EMULATE_CALLS,
            'Emulate all function calls',
            action_handler(self.action_emulate_calls_handler),
            None,
            'Emulate selected function'
        )

        idaapi.register_action(action_run)
        idaapi.register_action(action_reset)

        idaapi.register_action(action_toggle_reset)
        idaapi.update_action_checkable(ACTION_TOGGLE_RESET, True)
        idaapi.update_action_checked(ACTION_TOGGLE_RESET, self.reset_every_run)

        idaapi.register_action(action_toggle_unwind)
        idaapi.update_action_checkable(ACTION_TOGGLE_UNWIND, True)
        idaapi.update_action_checked(ACTION_TOGGLE_UNWIND, self.emu.enable_unwind)

        idaapi.register_action(action_toggle_comments)
        idaapi.update_action_checkable(ACTION_TOGGLE_COMMENTS, True)
        idaapi.update_action_checked(ACTION_TOGGLE_COMMENTS, self.show_comments)

        idaapi.register_action(action_calls)

        self.hooks = EmuItUIHooks()
        self.hooks.hook()

        self.banner()
        print(f'EmuIt {VERSION} started.')
        print(f'EmuIt run shortcut key is {PLUGIN_HOTKEY}.')

        return idaapi.PLUGIN_KEEP

    def action_run_handler(self, ctx):
        selection, start_ea, end_ea = ida_kernwin.read_range_selection(None)

        if not selection:
            ea = ida_kernwin.get_screen_ea()
            start_ea = idaapi.get_item_head(ea)
            end_ea = idaapi.get_item_end(ea)

        if self.reset_every_run:
            self.emu.reset()

        buffers = self.emu.run(start_ea, end_ea)

        if self.show_comments:
            candidates = filter(lambda x: x.metric_printable() > 0.6, buffers)
            for candidate in candidates:
                print(f'Add comment to 0x{candidate.write_instruction_ea:0X}')
                IdaCommentUtils.add_comment(candidate.write_instruction_ea, candidate.try_decode())
            IdaUiUtils.refresh_current_viewer()

        for buffer in buffers:
            print(f'At 0x{buffer.write_instruction_ea:0X} to 0x{buffer.ea:0X}: {buffer}')

        print('EmuIt: finish')

    def action_emulate_calls_handler(self, ctx):
        for idx in ctx.chooser_selection:
            name, *_ = ida_kernwin.get_chooser_data(ctx.widget_title, idx)
            ea = idaapi.get_name_ea(idaapi.BADADDR, name)
            print(f'EmuIt: emulate calls of "{name}" (0x{ea:0X})')

            xrefs = list(idautils.XrefsTo(ea, idaapi.XREF_FAR))
            for xref in xrefs:
                print(f'EmuIt: emulate call of "name" at 0x{xref.frm:0X}')
                self.emu.smartcall(xref.frm)

    def action_reset_handler(self, ctx):
        self.emu.reset()

    def action_toggle_reset_handler(self, ctx):
        self.reset_every_run = bool(not self.reset_every_run)

    def action_toggle_unwind_handler(self, ctx):
        self.emu.enable_unwind = bool(not self.emu.enable_unwind)

    def action_toggle_comments_handler(self, ctx):
        self.show_comments = bool(not self.show_comments)

    def term(self):
        if hasattr(self, 'hooks'):
            self.hooks.unhook()
        print(f'EmuIt {VERSION} terminated.')

    def run(self, arg):
        print('call EmuIt from context menu (right click) in disassembly')


class EmuItUIHooks(idaapi.UI_Hooks):
    def populating_widget_popup(self, widget, popup):
        pass

    def finish_populating_widget_popup(self, widget, popup):
        attach = idaapi.attach_action_to_popup
        tree = PLUGIN_NAME

        widget_type = idaapi.get_widget_type(widget)
        if widget_type in {idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE}:
            attach(widget, popup, ACTION_RUN, f'{tree}/')
        elif widget_type == idaapi.BWN_FUNCS:
            attach(widget, popup, ACTION_EMULATE_CALLS, f'{tree}/')
        
        attach(widget, popup, ACTION_RESET, f'{tree}/')
        attach(widget, popup, 'separator', f'{tree}/')

        attach(widget, popup, ACTION_TOGGLE_RESET, f'{tree}/')
        attach(widget, popup, ACTION_TOGGLE_UNWIND, f'{tree}/')
        attach(widget, popup, ACTION_TOGGLE_COMMENTS, f'{tree}/')
        
        return 0


def action_handler(callback):
    class Handler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            callback(ctx)
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS
    return Handler()


plugin = EmuItPlugin()


def PLUGIN_ENTRY():
    global plugin
    return plugin
