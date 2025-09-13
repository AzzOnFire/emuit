import sys

from emuit import EmuItIda, IdaCallSelection

import idaapi
import ida_kernwin


ida_version = tuple(map(int, idaapi.get_kernel_version().split(".")))
assert (ida_version > (7, 4)), "ERROR: EmuIt requires IDA 7.4+"
assert (sys.version_info >= (3, 5)), "ERROR: EmuIt requires Python 3.6"


PLUGIN_NAME = 'EmuIt'
VERSION = '0.6.1'
PLUGIN_HOTKEY = 'Shift+C'

ACTION_RUN = 'EmuIt:run'
ACTION_RESET = 'EmuIt:reset'
ACTION_TOGGLE_RESET = 'EmuIt:toggle_reset'
ACTION_TOGGLE_SKIP_API_CALLS = 'EmuIt:toggle_skip_api_calls'
ACTION_TOGGLE_BEAUTIFY = 'EmuIt:toggle_beutify'


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
        #    print('EmuIt: try to rebase program and reopen IDB')
        #    return idaapi.PLUGIN_SKIP

        self.reset_every_run = True
        self.beautify = False

        action_run = idaapi.action_desc_t(
            ACTION_RUN,
            'EmuIt run',
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

        action_toggle_skip_api_calls = idaapi.action_desc_t(
            ACTION_TOGGLE_SKIP_API_CALLS,
            'Skip API calls',
            action_handler(self.action_toggle_skip_api_calls_handler),
            None,
            'Try to skip API calls, you may be lucky!'
        )

        action_toggle_beutify = idaapi.action_desc_t(
            ACTION_TOGGLE_BEAUTIFY,
            'Filter and beautify results',
            action_handler(self.action_toggle_beautify_handler),
            None,
            'Beatify output using metrics and ASCII/Unicode encoding'
        )

        idaapi.register_action(action_run)
        idaapi.register_action(action_reset)

        idaapi.register_action(action_toggle_reset)
        idaapi.update_action_checkable(ACTION_TOGGLE_RESET, True)
        idaapi.update_action_checked(ACTION_TOGGLE_RESET, self.reset_every_run)

        idaapi.register_action(action_toggle_skip_api_calls)
        idaapi.update_action_checkable(ACTION_TOGGLE_SKIP_API_CALLS, True)
        idaapi.update_action_checked(ACTION_TOGGLE_SKIP_API_CALLS,
                                     self.emu.skip_api_calls)

        idaapi.register_action(action_toggle_beutify)
        idaapi.update_action_checkable(ACTION_TOGGLE_BEAUTIFY, True)
        idaapi.update_action_checked(ACTION_TOGGLE_BEAUTIFY, self.beautify)

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
        results = self.emu.run(start_ea, end_ea)
        if self.beautify:
            results = results.pretty()

        for offset, data in results.items():
            print(hex(offset), data)
        print('EmuIt: finish')

    def action_emulate_call(self):
        call_ea = IdaCallSelection.get_selection()
        self.emu.smartcall(call_ea)

    def action_reset_handler(self):
        self.emu.reset()

    def action_toggle_reset_handler(self):
        self.reset_every_run = bool(not self.reset_every_run)

    def action_toggle_skip_api_calls_handler(self):
        self.emu.skip_api_calls = bool(not self.emu.skip_api_calls)

    def action_toggle_beautify_handler(self):
        self.beautify = bool(not self.beautify)

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

        tree = PLUGIN_NAME + " settings"
        attach = idaapi.attach_action_to_popup

        attach(widget, popup, ACTION_RUN, tree, idaapi.SETMENU_APP)
        attach(widget, popup, ACTION_RESET, f'{tree}/')
        attach(widget, popup, ACTION_TOGGLE_RESET, f'{tree}/')
        attach(widget, popup, ACTION_TOGGLE_SKIP_API_CALLS, f'{tree}/')
        attach(widget, popup, ACTION_TOGGLE_BEAUTIFY, f'{tree}/')

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
