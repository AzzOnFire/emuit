from typing import TYPE_CHECKING, Literal

from .regs import EmuRegs
if TYPE_CHECKING:
    from emuit import EmuIt

import unicorn as uc


class EmuArch(object):
    def __init__(self, emu: "EmuIt", uc_architecture: int, uc_mode: int):
        self._emu: "EmuIt" = emu
        self._uc_mode = uc_mode
        self._uc_architecture = uc_architecture
        self._engine = uc.Uc(uc_architecture, uc_mode)
        self._regs: EmuRegs = EmuRegs(self)

    @property
    def uc_architecture(self):
        return self._uc_architecture

    @property
    def uc_mode(self):
        return self._uc_mode

    @property
    def endian(self) -> Literal['little', 'big']:
        return 'big' if self.uc_mode & uc.unicorn_const.UC_MODE_BIG_ENDIAN else 'little' 

    @property
    def engine(self) -> uc.Uc:
        return self._engine

    @property
    def ptr_size(self) -> int:
        return self.bitness // 8

    @property
    def bitness(self) -> int:
        if self._uc_mode & uc.unicorn_const.UC_MODE_64:
            return 64
        if self._uc_mode & uc.unicorn_const.UC_MODE_32:
            return 32
        if self._uc_mode & uc.unicorn_const.UC_MODE_16:
            return 16

        raise ValueError('Invalid bitness specified in unicorn mode')

    @property
    def regs(self) -> EmuRegs:
        return self._regs

    def stack_push(self, value: int):
        if value.bit_count() > self.bitness:
            raise OverflowError()

        self.regs.arch_sp -= self.ptr_size
        self._emu.mem[self.regs.arch_sp] = value

    def stack_pop(self) -> int:
        data = self._emu.mem[self.regs.arch_sp:self.regs.arch_sp + self.ptr_size]
        self.regs.arch_sp += self.ptr_size
        return int.from_bytes(data, byteorder=self.endian)
