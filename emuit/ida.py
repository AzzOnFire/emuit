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
                self.log.error(f"argument {arg_ea:0X} emulation error")

        call_length = ida_ua.decode_insn(ida_ua.insn_t(), func_call_ea)
        return self.run(func_call_ea, func_call_ea + call_length)

    def _map_from_ida(self, address) -> bool:
        self.log.debug("trying to map segment")
        n = ida_segment.get_segm_num(address)
        seg = ida_segment.getnseg(n)
        if seg:
            self.log.debug(f"found corresponding segment: {ida_segment.get_segm_name(seg)}")
            range_start, range_end = seg.start_ea, seg.end_ea
        else:
            # Not inside a segment, e.g. padding between two segments. If the
            # page still holds segment data, map that page; mapping it blank
            # would hide the neighbouring segments' data for good.
            range_start = address & ~0xFFF
            range_end = range_start + 0x1000
            if not any(
                ida_segment.getnseg(i).start_ea < range_end
                and range_start < ida_segment.getnseg(i).end_ea
                for i in range(ida_segment.get_segm_qty())
            ):
                return False

        # Map only the pages of the range that are not mapped yet. Pages
        # already mapped hold data the emulated code may have written, and
        # are left alone. Nothing new to map means an earlier hook (or an
        # earlier fault) already mapped the range.
        new_runs = self._unmapped_page_runs(range_start, range_end)
        if not new_runs:
            return True

        # Map and fill one run at a time, so a failure never leaves a mapped
        # page without its data. Unicorn maps whole pages, so copy every IDA
        # segment sharing the new pages; otherwise a neighbour (e.g. __const
        # right after __text) is mapped but left as zeros, and never faults
        # in to be copied later.
        for run_start, run_end in new_runs:
            try:
                self.mem.map(run_start, run_end - run_start)
            except uc.UcError as e:
                self.log.error(f"unable to map from IDB to unicorn (0x{run_start:0X}), exception: {e}")
                return False

            try:
                for i in range(ida_segment.get_segm_qty()):
                    other = ida_segment.getnseg(i)
                    start_ea = max(other.start_ea, run_start)
                    end_ea = min(other.end_ea, run_end)
                    if start_ea < end_ea:
                        self._copy_from_ida(start_ea, end_ea)
            except uc.UcError as e:
                self.log.error(f"unable to copy from IDB to unicorn (0x{run_start:0X}), exception: {e}")
                return False

        self.log.debug("segment mapped and copied successfully")
        return True

    def _unmapped_page_runs(self, start_ea, end_ea):
        """Contiguous runs of 0x1000-aligned pages in [start_ea, end_ea) not mapped yet."""
        runs = []
        page = start_ea & ~0xFFF
        while page < end_ea:
            mapped = any(start <= page < end for start, end in self.mem.mapping)
            if not mapped:
                if runs and runs[-1][1] == page:
                    runs[-1] = (runs[-1][0], page + 0x1000)
                else:
                    runs.append((page, page + 0x1000))
            page += 0x1000
        return runs

    def _copy_from_ida(self, start_ea, end_ea):
        size = end_ea - start_ea
        result = ida_bytes.get_bytes_and_mask(start_ea, size)
        if result is None:
            self.mem.write(start_ea, b'\0' * size)
            return

        # IDA returns 0xFF for bytes without a value (uninitialized data);
        # the mask has one bit per byte, least significant bit first.
        # Replace those bytes with 0x00.
        data, mask = result
        data = bytearray(data[:size])
        for index, bits in enumerate(mask):
            if bits == 0xFF:
                continue
            base = index * 8
            if bits == 0:
                data[base:base + 8] = bytes(len(data[base:base + 8]))
                continue
            for bit in range(8):
                if base + bit < size and not (bits >> bit) & 1:
                    data[base + bit] = 0

        self.mem.write(start_ea, bytes(data))

    def _hook_mem_write_unmapped(self, uc, access, address, size, value, user_data):
        self.log.warning(f"unmapped write to 0x{address:0X}")
        # outside the database: a blank page, within the per-run limit
        if not self._map_from_ida(address) and not self._map_fallback_page(address):
            return False

        self._hook_mem_write(uc, access, address, size, value, user_data)
        return True

    def _hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        self.log.warning("unmapped fetch")
        return self._map_from_ida(address)

    def _hook_mem_read_unmapped(self, uc, access, address, size, value, user_data):
        self.log.warning(f"unmapped read from 0x{address:0X}")
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
            # TODO: include indirect_jump_insn() to unwinding ?
            if inslen and ida_idp.is_call_insn(insn):
                call_target_ea = insn.ops[0].addr
                purged = self.get_purged_bytes_number(call_target_ea)
                self.arch.add_unwind_record(
                    return_ea=self.arch.regs.arch_pc + inslen,
                    sp_value=self.arch.regs.arch_sp + purged,
                    label=idaapi.get_name(call_target_ea),
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

        self.log.debug("last instructions trace:")
        for insn_ea in self._insn_trace:
            flags = idaapi.GENDSM_REMOVE_TAGS
            line = idaapi.generate_disasm_line(insn_ea, flags)
            self.log.debug(f"0x{insn_ea:0X}: {line}")

        if self.arch.unwind():
            return True

        insn = ida_ua.insn_t()
        inslen = ida_ua.decode_insn(insn, self.arch.regs.arch_pc)
        if inslen:
            self.log.debug(f"Skip 1 instruction: 0x{self.arch.regs.arch_pc:0X}")
            self.arch.regs.arch_pc += inslen

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
