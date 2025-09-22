import idaapi
import ida_ida
import idc
import ida_kernwin

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
        cls.add_disassembly_comment(ea, text)
        cls.add_pseudocode_comment(ea, text)

    @staticmethod
    def add_comment_disassembly(ea: int, text: str):
        idc.set_cmt(ea, text, 0)

    @staticmethod
    def add_comment_pseudocode(ea: int, text: str):
        cfunc = idaapi.decompile(ea)
        if not cfunc:
            print("Failed to decompile function.")
            return

        tl = idaapi.treeloc_t()
        tl.ea = ea
        tl.itp = idaapi.ITP_SEMI  # comment after a semicolon

        cfunc.set_user_cmt(tl, text)
        cfunc.save_user_cmts()


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
        print(f"Selected address in disassembly: 0x{ea:x}")

        mnemonic = idc.print_insn_mnem(ea)
        if mnemonic.lower() != "call":
            print(f"Instruction at 0x{ea:x} is not a call: {mnemonic}")

        return ea

