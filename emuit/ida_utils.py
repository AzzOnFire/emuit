import idaapi
import ida_ida
import idc
import ida_kernwin
import ida_hexrays

import unicorn as uc


class IdaUcUtils(object):
    @staticmethod
    def get_uc_bitness() -> int:
        ida_version = tuple(map(int, idaapi.get_kernel_version().split(".")))
        if ida_version >= (9, 0):
            if ida_ida.inf_is_64bit():
                return uc.unicorn_const.UC_MODE_64
            elif ida_ida.inf_is_32bit_exactly():
                return uc.unicorn_const.UC_MODE_32
            elif ida_ida.inf_is_16bit():
                return uc.unicorn_const.UC_MODE_16
            else:
                raise ValueError("Unknown architecture bitness")
        else:
            info = idaapi.get_inf_structure()
            if info.is_64bit():
                return uc.unicorn_const.UC_MODE_64
            elif info.is_32bit():
                return uc.unicorn_const.UC_MODE_32
            else:
                return uc.unicorn_const.UC_MODE_16

    @staticmethod
    def get_processor_name() -> str:
        ida_version = tuple(map(int, idaapi.get_kernel_version().split(".")))
        if ida_version >= (9, 0):
            return ida_ida.inf_get_procname()
        else:
            info = idaapi.get_inf_structure()
            return info.procname.lower()

    @staticmethod
    def is_big_endian() -> bool:
        ida_version = tuple(map(int, idaapi.get_kernel_version().split(".")))
        if ida_version >= (9, 0):
            return ida_ida.inf_is_be()
        else:
            info = idaapi.get_inf_structure()
            return info.is_be()

    @classmethod
    def get_uc_arch_mode(cls):
        proc = cls.get_processor_name()
        mode = cls.get_uc_bitness()
        if proc == "metapc":
            arch = uc.unicorn_const.UC_ARCH_X86
        elif "arm" in proc:
            arch = (
                uc.unicorn_const.UC_ARCH_ARM64
                if mode == uc.unicorn_const.UC_MODE_64
                else uc.unicorn_const.UC_ARCH_ARM
            )
        elif "mips" in proc:  # mipsb, mipsl
            mode |= (
                uc.unicorn_const.UC_MODE_BIG_ENDIAN
                if "mispb" in proc
                else uc.unicorn_const.UC_MODE_LITTLE_ENDIAN
            )
            arch = uc.unicorn_const.UC_ARCH_MIPS
        elif "ppc" in proc:  # ppc, ppcl
            mode |= (
                uc.unicorn_const.UC_MODE_LITTLE_ENDIAN
                if "ppcl" in proc
                else uc.unicorn_const.UC_MODE_BIG_ENDIAN
            )
            arch = uc.unicorn_const.UC_ARCH_PPC
        elif "riscv" in proc:
            arch = uc.unicorn_const.UC_ARCH_RISCV
        elif "s390" in proc:  # s390 - 32bit, s390x - 64bit
            arch = uc.unicorn_const.UC_ARCH_S390X
        elif "tricore" in proc:
            arch = uc.unicorn_const.UC_ARCH_TRICORE
        elif "sparc" in proc:  # sparcb sparcl
            mode |= (
                uc.unicorn_const.UC_MODE_BIG_ENDIAN
                if "sparcb" in proc
                else uc.unicorn_const.UC_MODE_LITTLE_ENDIAN
            )
            arch = uc.unicorn_const.UC_ARCH_SPARC
        elif "68k" in proc:
            arch = uc.unicorn_const.UC_ARCH_M68K
        else:
            raise ValueError("Unsupported arch")

        return arch, mode


class IdaCommentUtils():
    @classmethod
    def add_comment(cls, ea: int, text: str):
        cls.add_comment_disassembly(ea, text)
        cls.add_comment_pseudocode(ea, text)

    @staticmethod
    def add_comment_disassembly(ea: int, text: str):
        idc.set_cmt(ea, text, 0)

    # many thanks to:
    # https://github.com/mrexodia/ida-pro-mcp/blob/main/src/ida_pro_mcp/mcp-plugin.py#L1153
    @staticmethod
    def add_comment_pseudocode(ea: int, text: str, function_comment: bool = True, merge=None):
        """With `merge`, a comment already at the line is combined with `text`:
        merge(existing, text) returns the new comment, or None to leave it."""
        error = ida_hexrays.hexrays_failure_t()
        cfunc = ida_hexrays.decompile_func(ea, error, ida_hexrays.DECOMP_WARNINGS)
        if not cfunc:
            return
        
        if function_comment and ea == cfunc.entry_ea:
            idc.set_func_cmt(ea, text, True)
            cfunc.refresh_func_ctext()
        
        eamap = cfunc.get_eamap()
        if ea not in eamap:
            print(f"Failed to set decompiler comment at {hex(ea)}")
            return
        
        nearest_ea = eamap[ea][0].ea

        # The placement below detects an invalid location by the function
        # having orphan comments, so set aside the existing ones (often the
        # analyst's, e.g. after retyping) and put them back afterwards.
        # Refresh first: a comment saved since this (cached) decompilation
        # was last refreshed counts as an orphan until then.
        cfunc.refresh_func_ctext()
        orphans = []
        if cfunc.has_orphan_cmts():
            before = IdaCommentUtils._user_cmts(cfunc.entry_ea)
            cfunc.del_orphan_cmts()
            cfunc.save_user_cmts()
            kept = IdaCommentUtils._user_cmts(cfunc.entry_ea)
            orphans = [(loc, cmt) for loc, cmt in before if (loc.ea, loc.itp) not in {(k.ea, k.itp) for k, _ in kept}]

        placed = None
        try:
            # Set the comment by trying the possible item types. ITP_BRACE2
            # (after the condition of an if/while/...) comes before the block
            # braces: for a call inside a condition, ITP_CURLY1 is valid too,
            # but puts the comment on the line of the enclosing block's '{'.
            tl = idaapi.treeloc_t()
            tl.ea = nearest_ea
            for itp in (idaapi.ITP_SEMI, idaapi.ITP_BRACE2, idaapi.ITP_CURLY1, idaapi.ITP_CURLY2):
                tl.itp = itp
                if merge is not None:
                    # the orphans were set aside, so a comment here is shown
                    existing = cfunc.get_user_cmt(tl, ida_hexrays.RETRIEVE_ALWAYS)
                    if existing:
                        merged = merge(existing, text)
                        if merged is not None:
                            cfunc.set_user_cmt(tl, merged)
                            cfunc.save_user_cmts()
                            cfunc.refresh_func_ctext()
                        placed = (tl.ea, tl.itp)
                        return
                cfunc.set_user_cmt(tl, text)
                cfunc.save_user_cmts()
                cfunc.refresh_func_ctext()
                if not cfunc.has_orphan_cmts():
                    placed = (tl.ea, tl.itp)
                    return
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()
        finally:
            for loc, cmt in orphans:
                if (loc.ea, loc.itp) != placed:  # never over the comment just set
                    cfunc.set_user_cmt(loc, cmt)
            if orphans:
                cfunc.save_user_cmts()
                cfunc.refresh_func_ctext()

    @staticmethod
    def _user_cmts(func_ea: int):
        """The function's pseudocode comments, as (treeloc_t, text) pairs."""
        result = []
        cmts = ida_hexrays.restore_user_cmts(func_ea)
        if cmts is None:
            return result
        it = ida_hexrays.user_cmts_begin(cmts)
        while it != ida_hexrays.user_cmts_end(cmts):
            src = ida_hexrays.user_cmts_first(it)
            loc = idaapi.treeloc_t()
            loc.ea, loc.itp = src.ea, src.itp
            result.append((loc, str(ida_hexrays.user_cmts_second(it))))
            it = ida_hexrays.user_cmts_next(it)
        ida_hexrays.user_cmts_free(cmts)
        return result

class IdaUiUtils():
    @staticmethod
    def refresh_current_viewer():
        viewer = ida_kernwin.get_current_viewer()
        widget_type = ida_kernwin.get_widget_type(viewer)

        if widget_type == ida_kernwin.BWN_PSEUDOCODE:
            vdui = idaapi.get_widget_vdui(viewer)
            if vdui:
                vdui.refresh_view(True)
    
    @staticmethod
    def get_selected_call_ea():
        ea = idc.get_screen_ea()

        mnemonic = idc.print_insn_mnem(ea)
        if mnemonic.lower() == "call":
            return ea

        return None

