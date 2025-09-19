import sys

from emuit import EmuItIda, IdaCallSelection, IdaComments

import idaapi
import ida_kernwin


ida_version = tuple(map(int, idaapi.get_kernel_version().split(".")))
assert (ida_version >= (8, 3)), "ERROR: EmuIt requires IDA 8.3+"
assert (sys.version_info >= (3, 8)), "ERROR: EmuIt requires Python 3.8"


PLUGIN_NAME = 'EmuIt'
VERSION = '0.6.5'
PLUGIN_HOTKEY = 'Shift+C'

ACTION_RUN = 'EmuIt:run'
ACTION_RESET = 'EmuIt:reset'
ACTION_TOGGLE_RESET = 'EmuIt:toggle_reset'
ACTION_TOGGLE_SKIP_EXTERNAL_CALLS = 'EmuIt:toggle_skip_external_calls'
ACTION_TOGGLE_COMMENTS = 'EmuIt:toggle_beutify'
ACTION_CALL = 'EmuIt:call'


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

        action_toggle_skip_external_calls = idaapi.action_desc_t(
            ACTION_TOGGLE_SKIP_EXTERNAL_CALLS,
            'Skip external calls',
            action_handler(self.action_toggle_skip_external_calls_handler),
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

        action_call = idaapi.action_desc_t(
            ACTION_CALL,
            'Emulate selected function',
            action_handler(self.action_emulate_call_handler),
            None,
            'Emulate selected function in pseudocode/disassembly view'
        )

        idaapi.register_action(action_run)
        idaapi.register_action(action_reset)

        idaapi.register_action(action_toggle_reset)
        idaapi.update_action_checkable(ACTION_TOGGLE_RESET, True)
        idaapi.update_action_checked(ACTION_TOGGLE_RESET, self.reset_every_run)

        idaapi.register_action(action_toggle_skip_external_calls)
        idaapi.update_action_checkable(ACTION_TOGGLE_SKIP_EXTERNAL_CALLS, True)
        idaapi.update_action_checked(ACTION_TOGGLE_SKIP_EXTERNAL_CALLS,
                                     self.emu.skip_external_calls)

        idaapi.register_action(action_toggle_comments)
        idaapi.update_action_checkable(ACTION_TOGGLE_COMMENTS, True)
        idaapi.update_action_checked(ACTION_TOGGLE_COMMENTS, self.show_comments)

        idaapi.register_action(action_call)

        self.hooks = EmuItUIHooks()
        self.hooks.hook()

        self.banner()
        print(f'EmuIt {VERSION} started.')
        print(f'EmuIt run shortcut key is {PLUGIN_HOTKEY}.')

        return idaapi.PLUGIN_KEEP

    def action_run_handler(self):
        selection, start_ea, end_ea = ida_kernwin.read_range_selection(None)

        if not selection:
            ea = ida_kernwin.get_screen_ea()
            start_ea = idaapi.get_item_head(ea)
            end_ea = idaapi.get_item_end(ea)

        if self.reset_every_run:
            self.emu.reset()

        print(f'EmuIt: running {start_ea:08X} - {end_ea:08X}')
        buffers = self.emu.run(start_ea, end_ea)

        if self.show_comments:
            candidate = max(buffers, key=lambda x: x.metric_printable())
            IdaComments.add_comment(candidate.write_instruction_ea, candidate.try_decode())

        for buffer in buffers:
            print(hex(buffer.write_instruction_ea), hex(buffer.ea), buffer)

        print('EmuIt: finish')

    def action_emulate_call_handler(self):
        call_ea = IdaCallSelection.get_selected_call()
        if not call_ea:
            print('EmuIt: no function selected')
            return

        self.emu.smartcall(call_ea)

    def action_reset_handler(self):
        self.emu.reset()

    def action_toggle_reset_handler(self):
        self.reset_every_run = bool(not self.reset_every_run)

    def action_toggle_skip_external_calls_handler(self):
        self.emu.skip_external_calls = bool(not self.emu.skip_external_calls)

    def action_toggle_comments_handler(self):
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
        if (idaapi.get_widget_type(widget) not in {idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE}):
            return 0

        tree = PLUGIN_NAME
        attach = idaapi.attach_action_to_popup

        attach(widget, popup, ACTION_RUN, f'{tree}/')
        attach(widget, popup, ACTION_RESET, f'{tree}/')
        attach(widget, popup, ACTION_TOGGLE_RESET, f'{tree}/')
        attach(widget, popup, ACTION_TOGGLE_SKIP_EXTERNAL_CALLS, f'{tree}/')
        attach(widget, popup, ACTION_TOGGLE_COMMENTS, f'{tree}/')
        attach(widget, popup, ACTION_CALL, f'{tree}/')

        return 0


def action_handler(callback):
    class Handler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            callback()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS
    return Handler()


plugin = EmuItPlugin()


def PLUGIN_ENTRY():
    global plugin
    return plugin
