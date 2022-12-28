from typing import Union

from .base import EmuIt

import unicorn as uc


class EmuItX86_64(EmuIt):
    STACK_BASE = 0x200000
    STACK_SIZE = 0x150000

    def __init__(self, bitness: int):
        mode = {32: uc.UC_MODE_32, 64: uc.UC_MODE_64}.get(bitness)
        if mode is None:
            raise ValueError('Bitsize must be 32 (x86) or 64 (x64)')

        super().__init__(uc.UC_ARCH_X86, mode, bitness)

    def stdcall(self, start_ea: int, end_ea: int, *stack_args):
        for arg in reversed(stack_args):
            self.push(self.parse_argument(arg))

        self.push(0)    # dummy return address
        result = self.run(start_ea, end_ea)
        self.pop()

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
        self._init_stack()

    def _init_stack(self):
        base, size = self.STACK_BASE, self.STACK_SIZE
        if not self.query(base):
            self.malloc_ex(base, size)

        self['*SP'] = base + (size // 2) & ~0xFF
        self['*BP'] = base + (3 * size // 4) & ~0xFF

    def push(self, value: Union[int, str, bytes]):
        self['*SP'] -= self.bytesize

        if isinstance(value, (bytes, str)):
            buffer = self.malloc(len(value))
            self[buffer] = value
            value = buffer

        self[self['*SP']] = value

    def pop(self):
        sp = self['*SP']
        data = self[sp:sp + self.bytesize]
        self['*SP'] += self.bytesize
        return data

    def _reg_parse(self, register: str):
        if register.startswith('*'):
            prefix = 'R' if self.bitsize == 64 else 'E'
            register = register.replace('*', prefix)

        register = register.upper()
        return getattr(uc.x86_const, f'UC_X86_REG_{register}')
