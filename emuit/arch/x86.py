from typing import TYPE_CHECKING

from .base import EmuArch

if TYPE_CHECKING:
    from emuit import EmuIt

import unicorn as uc


class EmuArchX86(EmuArch):

    def __init__(self, emu: "EmuIt", uc_mode: int):
        super().__init__(
            emu,
            uc_architecture=uc.unicorn_const.UC_ARCH_X86,
            uc_mode=uc_mode,
        )

    def stdcall(self, start_ea: int, end_ea: int, *stack_args):
        for arg in reversed(stack_args):
            self.stack_push(arg)

        self.stack_push(0)    # dummy return address
        result = self._emu.run(start_ea, end_ea)
        self.stack_pop()

        return result

    def thiscall(self, start_ea: int, end_ea: int, this: int, *stack_args):
        self.regs['ECX'] = this
        return self.stdcall(start_ea, end_ea, *stack_args)

    def fastcall(self, start_ea: int, end_ea: int,
                 rcx=None, rdx=None, r8=None, r9=None, *stack_args):
        if rcx is not None: self.regs['RCX'] = rcx
        if rdx is not None: self.regs['RDX'] = rdx
        if r8 is not None: self.regs['R8'] = r8
        if r9 is not None: self.regs['R9'] = r9

        return self.stdcall(start_ea, end_ea, *stack_args)
