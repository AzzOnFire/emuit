import sys
import traceback

import idaapi
import idc
import ida_hexrays
import ida_funcs
import ida_kernwin
import ida_name
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

    # Longer results are cut in comments: IDA keeps only 1024 characters of a
    # disassembly comment, and a pseudocode comment is shown as one line.
    MAX_COMMENT_LENGTH = 1024

    def banner(self):
        print('=' * 52, '\n', ' ' * 52)
        print(r'  ______     __    __     __  __     __     ______  ')
        print(r' /\  ___\   /\ "-./  \   /\ \/\ \   /\ \   /\__  _\ ')
        print(r' \ \  __\   \ \ \-./\ \  \ \ \_\ \  \ \ \  \/_/\ \/ ')
        print(r'  \ \_____\  \ \_\ \ \_\  \ \_____\  \ \_\    \ \_\ ')
        print(r'   \/_____/   \/_/  \/_/   \/_____/   \/_/     \/_/ ')
        print(' ' * 52, '\n', '=' * 52)

    def init(self):
        try:
            self.emu = EmuItIda()
        except Exception as e:
            traceback_str = traceback.format_exc()  # Capture the traceback as a string
            print('EmuIt: an error occurred during initialization:', traceback_str)
            return idaapi.PLUGIN_SKIP

        self.reset_every_run = True
        self.show_comments = True

        self.register_action(ACTION_RUN, 'Run', self.action_run_handler, hotkey=PLUGIN_HOTKEY)
        self.register_action(ACTION_RESET, 'Reset state', self.action_reset_handler)
        self.register_action(ACTION_TOGGLE_RESET, 'Reset on every run', self.action_toggle_reset_handler)
        idaapi.update_action_checkable(ACTION_TOGGLE_RESET, True)
        idaapi.update_action_checked(ACTION_TOGGLE_RESET, self.reset_every_run)
        self.register_action(ACTION_TOGGLE_UNWIND, 'Unwind on error', self.action_toggle_unwind_handler)
        idaapi.update_action_checkable(ACTION_TOGGLE_UNWIND, True)
        idaapi.update_action_checked(ACTION_TOGGLE_UNWIND, self.emu.enable_unwind)
        self.register_action(ACTION_TOGGLE_COMMENTS, 'Show comments', self.action_toggle_comments_handler)
        idaapi.update_action_checkable(ACTION_TOGGLE_COMMENTS, True)
        idaapi.update_action_checked(ACTION_TOGGLE_COMMENTS, self.show_comments)
        self.register_action(ACTION_EMULATE_CALLS, 'Emulate all function calls', self.action_emulate_calls_handler)

        self.hooks = EmuItUIHooks()
        self.hooks.hook()

        self.banner()
        print(f'EmuIt: started. Version {VERSION}')
        print(f'EmuIt: shortcut key is {PLUGIN_HOTKEY}')

        return idaapi.PLUGIN_KEEP

    def register_action(self, action, label, handler, hotkey = None, description = None):
        idaapi.register_action(
            idaapi.action_desc_t(
                action,
                label,
                action_handler(handler),
                hotkey,
                description,
            )
        )

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
            candidates = filter(lambda x: x.metric_decodable() > 0.6, buffers)
            for candidate in candidates:
                self.emu.log.info(f'add comment to 0x{candidate.write_instruction_ea:0X}')
                IdaCommentUtils.add_comment(candidate.write_instruction_ea, candidate.try_decode())
            IdaUiUtils.refresh_current_viewer()

        for buffer in buffers:
            self.emu.log.info(f'(PC:0x{buffer.write_instruction_ea:0X}) 0x{buffer.ea:0X}: {buffer}')

        self.emu.log.info('finish')

    def action_emulate_calls_handler(self, ctx):
        if ctx.widget_type != idaapi.BWN_FUNCS:
            self.emu.log.error('select the functions in the Functions view')
            return

        # an indirect call (e.g. through a jump table) can reference several
        # of the selected functions: emulate each call site once
        done = set()
        for idx in ctx.chooser_selection:
            # The selection holds function numbers. Looking the function up
            # by its displayed name fails: get_chooser_data() returns None
            # for this view (IDA 9.4), and C++ names are shown demangled.
            func = ida_funcs.getn_func(idx)
            if func is None:
                continue
            ea = func.start_ea
            name = ida_name.get_short_name(ea)
            self.emu.log.info(f'emulate calls of "{name}" (0x{ea:0X})')

            # Only call references. Data references (function pointer tables,
            # vtables, exception tables) and tail-call jumps can't be emulated
            # as calls. The reference type is used rather than decoding the
            # source: is_call_insn() raises on data addresses that don't
            # decode, and returns True for data bytes that happen to decode
            # as a call.
            call_sites = [
                xref.frm
                for xref in idautils.XrefsTo(ea, idaapi.XREF_FAR)
                if xref.type in (idaapi.fl_CN, idaapi.fl_CF) and xref.frm not in done
            ]
            done.update(call_sites)
            for call_ea in call_sites:
                self.emu.log.info(f'emulate call of "{name}" at 0x{call_ea:0X}')
                if self.reset_every_run:
                    self.emu.reset()

                # one failing call site must not stop the remaining ones
                try:
                    buffers = self.emu.smartcall(call_ea)
                    self._show_call_results(call_ea, buffers)
                except Exception as e:
                    self.emu.log.error(f'call at 0x{call_ea:0X} failed: {e}')

        IdaUiUtils.refresh_current_viewer()
        self.emu.log.info('finish')

    def _show_call_results(self, call_ea, buffers):
        for buffer in buffers:
            self.emu.log.info(f'(call 0x{call_ea:0X}) 0x{buffer.ea:0X}: {buffer}')

        if not self.show_comments:
            return

        # Comment at the call site: every call to the function shares the
        # same write instructions inside it, so comments there would
        # overwrite each other.
        decoded = []
        for buffer in buffers:
            if buffer.metric_decodable() <= 0.6:
                continue
            # one buffer that fails to decode must not lose the others
            try:
                text = buffer.try_decode()
            except Exception as e:
                self.emu.log.warning(f'(call 0x{call_ea:0X}) cannot decode 0x{buffer.ea:0X}: {e}')
                continue
            if text:
                decoded.append(text)
        if decoded:
            text = ' | '.join(decoded)
            if len(text) > self.MAX_COMMENT_LENGTH:
                text = text[:self.MAX_COMMENT_LENGTH - 3] + '...'
            self.emu.log.info(f'add comment to 0x{call_ea:0X}')
            self._comment_call_site(call_ea, text)

    def _comment_call_site(self, call_ea, text):
        # Call sites often carry the analyst's own comments: add the result
        # to them instead of replacing them, in both views.
        disassembly = self._merge_comment(idc.get_cmt(call_ea, 0), text)
        if disassembly is not None:
            IdaCommentUtils.add_comment_disassembly(call_ea, disassembly)

        if not ida_hexrays.init_hexrays_plugin():
            return  # no decompiler for this database

        # A call can be a function's first instruction: comment the call's
        # line only, keeping the function's own comment
        IdaCommentUtils.add_comment_pseudocode(
            call_ea, text, function_comment=False, merge=self._merge_comment
        )

    @staticmethod
    def _merge_comment(existing, text):
        """Comment to write, or None if `text` is already there."""
        if not existing:
            return text
        if text in existing.splitlines():
            return None
        return f'{existing}\n{text}'

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
        print('EmuIt: terminated')

    def run(self, arg):
        print('EmuIt: call from context menu (right click) in pseudocode/disassembly view')


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
