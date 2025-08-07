from typing import Any, Union

from .x86_64 import EmuItX86_64

import idaapi
import ida_ida
import ida_segment
import ida_bytes
import ida_ua
import ida_allins
import idautils
import ida_idp
import ida_funcs
import ida_name
import idc


class EmuItIda(EmuItX86_64):
    SKIP_WRITE_MEM_INSNS = {
        ida_allins.NN_call, ida_allins.NN_callfi, ida_allins.NN_callni,
        ida_allins.NN_enter, ida_allins.NN_enterw,
        ida_allins.NN_enterd, ida_allins.NN_enterq,
        ida_allins.NN_pusha, ida_allins.NN_pushaw,
        ida_allins.NN_pushad, ida_allins.NN_pushaq,
        ida_allins.NN_pushfw, ida_allins.NN_pushf,
        ida_allins.NN_pushfd, ida_allins.NN_pushfq,
    }

    def __init__(self, skip_api_calls=False):
        self.skip_api_calls = skip_api_calls
        bitness = 64 if ida_ida.inf_is_64bit() else 32

        super().__init__(bitness=bitness)

    def luckycall(self, func_call_ea: int, force: bool = True):
        refs = list(idautils.CodeRefsFrom(func_call_ea, 0x0))
        if len(refs) != 1:
            raise ValueError('Wrong call address '
                             '(must point to existing function)')

        func_ea = refs[0]
        func = ida_funcs.get_func(func_ea)
        ea = func.start_ea

        if force:
            tinfo = idaapi.tinfo_t()
            if not idaapi.get_tinfo(tinfo, ea):
                raise ValueError(f"No type information for function at 0x{ea:X}")
            
            if not idaapi.apply_tinfo(ea, tinfo, idaapi.TINFO_DEFINITE):
                raise ValueError(f"Failed to apply prototype at 0x{ea:X}")
            
            idc.plan_and_wait(ea, ea + 1)
        elif func.regargqty != 0:
            raise AttributeError(f'Please manually edit/apply function {ea:0X} '
                                    f'prototype or provide "force" flag')

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

    def fastcall(self, function: Union[int, str],
                 rcx=None, rdx=None, r8=None, r9=None, *stack_args):
        func_ea = self._resolve_name(function)
        func = ida_funcs.get_func(func_ea)
        return super().fastcall(
            func.start_ea,
            func.end_ea,
            rcx=rcx, rdx=rdx, r8=r8, r9=r9,
            *stack_args)

    def thiscall(self, function: Union[int, str], this: int, *stack_args):
        func_ea = self._resolve_name(function)
        func = ida_funcs.get_func(func_ea)
        return super().thiscall(func.start_ea, func.end_ea, this, *stack_args)

    def stdcall(self, function: Union[int, str], *stack_args):
        func_ea = self._resolve_name(function)
        func = ida_funcs.get_func(func_ea)
        return super().stdcall(func.start_ea, func.end_ea, *stack_args)

    def _hook_unmapped(self, uc, access, address, size, value, data):
        n = ida_segment.get_segm_num(address)
        seg = ida_segment.getnseg(n)
        if not seg:
            return False

        try:
            size = seg.end_ea - seg.start_ea
            self.malloc_ex(seg.start_ea, size)
            self[seg.start_ea] = ida_bytes.get_bytes(seg.start_ea, size)
        except Exception as e:
            print(e)
            return False

        return True

    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        ip = self['*IP']
        insn = ida_ua.insn_t()
        inslen = ida_ua.decode_insn(insn, ip)
        if not inslen or insn.itype in self.SKIP_WRITE_MEM_INSNS:
            return

        user_data.update([address + offset for offset in range(0, size)])

    def _hook_code(self, uc, address, size, user_data):
        if self.skip_api_calls:
            ip = self['*IP']
            self._skip_api_call(ip)

    @staticmethod
    def _resolve_name(value: Union[Any, str]):
        if isinstance(value, str):
            ea = idaapi.get_name_ea(idaapi.BADADDR, value)
            if ea != idaapi.BADADDR:
                return ea

        return value

    def __setitem__(self, destination: Union[str, int], value: Any):
        if isinstance(destination, str):
            destination = self._resolve_name(destination)

        return super().__setitem__(destination, value)

    def __getitem__(self, source: Union[str, slice]):
        if isinstance(source, str):
            source = self._resolve_name(source)
        elif isinstance(source, slice):
            start = self._resolve_name(source.start)
            stop = self._resolve_name(source.stop)
            source = slice(start, stop)

        return super().__getitem__(source)

    def _skip_api_call(self, call_ea: int):
        insn = ida_ua.insn_t()
        inslen = ida_ua.decode_insn(insn, call_ea)
        if not inslen:
            return

        if ida_idp.is_call_insn(insn) and self._is_api_call(call_ea):
            arg_addrs = idaapi.get_arg_addrs(call_ea)
            arg_addrs = arg_addrs if arg_addrs is not None else []

            print(f'Skip API call at 0x{call_ea:0X}...')
            for arg_ea in arg_addrs:
                arg_insn = ida_ua.insn_t() 
                if not ida_ua.decode_insn(arg_insn, arg_ea):
                    continue

                # TODO understand why argsize attribute
                # do not working with api calls
                if 'push' in arg_insn.get_canon_mnem():
                    self['*SP'] += self.bytesize

            self['*IP'] += inslen

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
