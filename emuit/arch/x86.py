from typing import TYPE_CHECKING

import unicorn as uc

from .base import EmuArch

if TYPE_CHECKING:
    from emuit import EmuIt


class EmuArchX86(EmuArch):
    def __init__(self, emu: "EmuIt", uc_mode: int):
        super().__init__(
            emu,
            uc_architecture=uc.unicorn_const.UC_ARCH_X86,
            uc_mode=uc_mode,
        )

    def stdcall(self, start_ea: int, end_ea: int, *args):
        for arg in reversed(args):
            self.stack_push(arg)

        self.stack_push(0)  # dummy return address
        result = self._emu.run(start_ea, end_ea)
        self.stack_pop()

        return result

    def thiscall(self, start_ea: int, end_ea: int, *args):
        if len(args) > 0:
            self.regs["*CX"], *stack_args = args
        else:
            stack_args = args

        return self.stdcall(start_ea, end_ea, *stack_args)

    def fastcall(self, start_ea: int, end_ea: int, *args):
        if len(args) > 0:
            self.regs["RCX"], *args = args
        if len(args) > 0:
            self.regs["RDX"], *args = args
        if len(args) > 0:
            self.regs["R8"], *args = args
        if len(args) > 0:
            self.regs["R9"], *args = args

        return self.stdcall(start_ea, end_ea, *args)
