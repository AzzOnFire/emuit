import idaapi
import ida_ida
import idc
import ida_hexrays
import ida_funcs

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
                raise ValueError('Unknown architecture bitness')
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
            arch = uc.unicorn_const.UC_ARCH_ARM64 if mode == uc.unicorn_const.UC_MODE_64 else uc.unicorn_const.UC_ARCH_ARM
        elif "mips" in proc:    # mipsb, mipsl
            mode |= uc.unicorn_const.UC_MODE_BIG_ENDIAN if 'mispb' in proc else uc.unicorn_const.UC_MODE_LITTLE_ENDIAN
            arch = uc.unicorn_const.UC_ARCH_MIPS
        elif "ppc" in proc:     # ppc, ppcl
            mode |= uc.unicorn_const.UC_MODE_LITTLE_ENDIAN if 'ppcl' in proc else uc.unicorn_const.UC_MODE_BIG_ENDIAN
            arch = uc.unicorn_const.UC_ARCH_PPC
        elif "riscv" in proc:
            arch = uc.unicorn_const.UC_ARCH_RISCV
        elif "s390" in proc:    # s390 - 32bit, s390x - 64bit
            arch = uc.unicorn_const.UC_ARCH_S390X   
        elif "tricore" in proc:
            arch = uc.unicorn_const.UC_ARCH_TRICORE
        elif "sparc" in proc:   # sparcb sparcl
            mode |= uc.unicorn_const.UC_MODE_BIG_ENDIAN if 'sparcb' in proc else uc.unicorn_const.UC_MODE_LITTLE_ENDIAN
            arch = uc.unicorn_const.UC_ARCH_SPARC   
        elif "68k" in proc:
            arch = uc.unicorn_const.UC_ARCH_M68K

        return arch, mode


class IdaCallSelection:
    @classmethod
    def get_selected_call(cls):
        widget_type = ida_kernwin.get_widget_type(ida_kernwin.get_current_viewer())
        if widget_type == ida_kernwin.BWN_DISASM:
            print("Current view: Disassembly")
            return cls.get_selected_call_disassembly()
        elif widget_type == ida_kernwin.BWN_PSEUDOCODE:
            print("Current view: Pseudocode")
            return cls.get_selected_call_pseudocode()
        else:
            print("Current view: Other")

    @staticmethod
    def get_selected_call_disassembly():
        ea = idc.get_screen_ea()
        print(f"Selected address in disassembly: 0x{ea:x}")

        mnemonic = idc.print_insn_mnem(ea)
        if mnemonic.lower() != "call":
            print(f"Instruction at 0x{ea:x} is not a call: {mnemonic}")
        
        return ea
            
    @staticmethod
    def get_selected_call_pseudocode():
        ea = idc.get_screen_ea()
        func = idaapi.get_func(ea)
        if not func:
            print("No function at cursor")
            return None

        cfunc = ida_hexrays.decompile(func)
        if not cfunc:
            print("Failed to decompile function")
            return None

        def find_call_node(ctree_item):
            if ctree_item is None:
                return None

            if ctree_item.op == ida_hexrays.cot_call and ctree_item.ea == ea:
                return ctree_item
            if ctree_item.is_expr():
                if hasattr(ctree_item, 'x') and ctree_item.x:
                    found = find_call_node(ctree_item.x)
                    if found:
                        return found
                if hasattr(ctree_item, 'a') and ctree_item.a:
                    for arg in ctree_item.a:
                        found = find_call_node(arg)
                        if found:
                            return found
            if ctree_item.op == ida_hexrays.cit_block:
                for stmt in ctree_item.cblock:
                    found = find_call_node(stmt)
                    if found:
                        return found
            if ctree_item.op == ida_hexrays.cit_expr:
                return find_call_node(ctree_item.cexpr)
            return None

        call_node = find_call_node(cfunc.body)
        if not call_node:
            print("No call node found at cursor")
            return None

        return call_node.ea
