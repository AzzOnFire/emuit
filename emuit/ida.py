from typing import Any, Union

from .emuit import EmuIt
from .ida_utils import IdaUcUtils

import unicorn as uc
import idaapi
import ida_segment
import ida_bytes
import ida_ua
import ida_allins
import idautils
import ida_idp
import ida_funcs
import ida_name
import ida_hexrays
import ida_typeinf
import ida_nalt
import idc


class EmuItIda(EmuIt):
    SKIP_WRITE_MEM_INSNS = {
        ida_allins.NN_call,
        ida_allins.NN_callfi,
        ida_allins.NN_callni,
        ida_allins.NN_enter,
        ida_allins.NN_enterw,
        ida_allins.NN_enterd,
        ida_allins.NN_enterq,
        ida_allins.NN_pusha,
        ida_allins.NN_pushaw,
        ida_allins.NN_pushad,
        ida_allins.NN_pushaq,
        ida_allins.NN_pushfw,
        ida_allins.NN_pushf,
        ida_allins.NN_pushfd,
        ida_allins.NN_pushfq,
    }

    def __init__(self, enable_unwind: bool = True):
        self.enable_unwind = enable_unwind
        uc_architecture, uc_mode = IdaUcUtils.get_uc_arch_mode()
        super().__init__(uc_architecture, uc_mode)

    def smartcall(self, func_call_ea: int):
        refs = list(idautils.CodeRefsFrom(func_call_ea, 0x0))
        if len(refs) != 1:
            raise ValueError("Wrong call address (must point to existing function)")

        func_ea = refs[0]
        func = ida_funcs.get_func(func_ea)
        ea = func.start_ea

        tinfo = idaapi.tinfo_t()
        if not idaapi.get_tinfo(tinfo, ea):
            ida_hexrays.decompile(ea)
            if not idaapi.get_tinfo(tinfo, ea):
                raise ValueError(f"No type information for function at 0x{ea:X}")

        if not idaapi.apply_callee_tinfo(func_call_ea, tinfo):
            raise ValueError(f"Failed to apply prototype at 0x{func_call_ea:0X}")

        for arg_ea in idaapi.get_arg_addrs(func_call_ea):
            length = ida_ua.decode_insn(ida_ua.insn_t(), arg_ea)
            if length == 0:
                continue

            try:
                self.run(arg_ea, arg_ea + length)
            except Exception:
                print("Argument {arg_ea:0X} emulation error")

        call_length = ida_ua.decode_insn(ida_ua.insn_t(), func_call_ea)
        return self.run(func_call_ea, func_call_ea + call_length)

    def _map_from_ida(self, address) -> bool:
        n = ida_segment.get_segm_num(address)
        seg = ida_segment.getnseg(n)
        if not seg:
            return False

        seg_size = seg.end_ea - seg.start_ea
        # TODO fix Exception to Unicorn specific exception
        print("Try to map", hex(seg.start_ea), hex(seg_size))
        try:
            self.mem.map(seg.start_ea, seg_size)
        except uc.UcError as e:
            print(e)

        try:
            print(
                "Copy from database to unicorn memory", hex(seg.start_ea), hex(seg_size)
            )
            self.mem[seg.start_ea] = ida_bytes.get_bytes(seg.start_ea, seg_size)
        except uc.UcError as e:
            print(e)
            return False

        return True

    def _hook_mem_write_unmapped(self, uc, access, address, size, value, user_data):
        if not self._map_from_ida(address):
            self.mem.map(address, 0x1000)

        return self._hook_mem_write(user_data, address, size)

    def _hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        return self._map_from_ida(address)

    def _hook_mem_read_unmapped(self, uc, access, address, size, value, user_data):
        print("Read unmapped", hex(address), hex(size), value)
        return self._map_from_ida(address)

    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        insn = ida_ua.insn_t()
        inslen = ida_ua.decode_insn(insn, self.arch.regs.arch_pc)
        if not inslen or insn.itype in self.SKIP_WRITE_MEM_INSNS:
            return

        super()._hook_mem_write(uc, access, address, size, value, user_data)

    def _hook_code(self, uc, address, size, user_data):
        super()._hook_code(uc, address, size, user_data)

        if self.enable_unwind:
            insn = ida_ua.insn_t()
            inslen = ida_ua.decode_insn(insn, self.arch.regs.arch_pc)
            if inslen and ida_idp.is_call_insn(insn): # NOTE: indirect_jump_insn() ?
                call_target_ea = insn.ops[0].addr
                purged = self.get_purged_bytes_number(call_target_ea)
                self.arch.add_unwind_record(
                    return_ea=self.arch.regs.arch_pc + inslen,
                    sp_value=self.arch.regs.arch_sp + purged
                )

    @staticmethod
    def get_purged_bytes_number(func_ea: int) -> int:
        tif = ida_typeinf.tinfo_t()
        if not ida_nalt.get_tinfo(tif, func_ea):
            return 0

        if tif.is_funcptr():
            data = ida_typeinf.ptr_type_data_t()
            if not tif.get_ptr_details(data):
                return 0
    
            tif = data.obj_type
        
        return tif.calc_purged_bytes()

    def _hook_error(self, e):
        super()._hook_error(e)

        for insn_ea in self._insn_trace:
            flags = idaapi.GENDSM_REMOVE_TAGS
            line = idaapi.generate_disasm_line(insn_ea, flags)
            print(hex(insn_ea), line)

        print("Unwinding...")
        self.arch.unwind()
        return True

    @staticmethod
    def _get_name_ea(value: Union[Any, str]):
        if isinstance(value, str):
            ea = idaapi.get_name_ea(idaapi.BADADDR, value)
            if ea != idaapi.BADADDR:
                return ea

        return value

    @staticmethod
    def _is_api_call(call_ea: int):
        xref = next(idautils.XrefsFrom(call_ea, idaapi.XREF_FAR), None)
        if xref is None:
            return False

        ea = xref.to
        flags = idc.get_func_attr(ea, idc.FUNCATTR_FLAGS)
        if flags & (idaapi.FUNC_LIB | idaapi.FUNC_THUNK):
            name_flags = ida_name.GN_VISIBLE | ida_name.calc_gtn_flags(0, ea)
            name = idc.get_name(ea, name_flags)
            return bool(name)

        return False
