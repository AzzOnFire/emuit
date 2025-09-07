from typing import Union

from .base import EmuArch
from emuit import EmuIt

import unicorn as uc


class EmuArchX86(EmuArch):
    STACK_BASE = 0x200000
    STACK_SIZE = 0x150000

    def __init__(self, emu: EmuIt):
        mode = {
            32: uc.UC_MODE_32, 
            64: uc.UC_MODE_64
        }.get(bitness)

        if mode is None:
            raise ValueError('Bitsize must be 32 (x86) or 64 (x64)')

        super().__init__(uc.UC_ARCH_X86, mode, bitness)

    def stdcall(self, start_ea: int, end_ea: int, *stack_args):
        for arg in reversed(stack_args):
            self.stack_push(self.parse_argument(arg))

        self.stack_push(0)    # dummy return address
        result = self._emu.run(start_ea, end_ea)
        self.stack_pop()

        return result

    def thiscall(self, start_ea: int, end_ea: int, this: int, *stack_args):
        self['ECX'] = this
        return self.stdcall(start_ea, end_ea, *stack_args)

    def fastcall(self, start_ea: int, end_ea: int,
                 rcx=None, rdx=None, r8=None, r9=None, *stack_args):
        if rcx is not None: self['RCX'] = rcx
        if rdx is not None: self['RDX'] = rdx
        if r8 is not None: self['R8'] = r8
        if r9 is not None: self['R9'] = r9

        return self.stdcall(start_ea, end_ea, *stack_args)

    def reset(self):
        for start, _ in self.mapping:
            self.free(start)
        
        try:
            self._init_stack()
        except Exception as e:
            print('Unable to allocate stack')
            pass

    def _init_stack(self):
        base, size = self.STACK_BASE, self.STACK_SIZE
        if not self.query(base):
            self._emu.mem.malloc_ex(base, size)

        self['*SP'] = base + (size // 2) & ~0xFF
        self['*BP'] = base + (3 * size // 4) & ~0xFF

    def _reg_parse(self, register: str):
        if register.startswith('*'):
            prefix = 'R' if self.bitsize == 64 else 'E'
            register = register.replace('*', prefix)

        register = register.upper()
        return getattr(uc.x86_const, f'UC_X86_REG_{register}')
