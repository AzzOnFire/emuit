from abc import ABC, abstractmethod
from collections import Counter
from typing import Union, Optional, Tuple

from .regs import EmuRegs
from emuit import EmuIt

import unicorn as uc


class EmuArch(ABC):
    def __init__(self, emu: EmuIt, bitness: int = 64):
        self._emu: EmuIt = emu
        self._regs: EmuRegs = EmuRegs(emu)
        self._bitness = bitness

    @property
    def bitness(self) -> int:
        return bitness

    @property
    def regs(self) -> EmuRegs:
        return self._regs

    def stack_push(self, value: Union[int, str, bytes]):
        self.regs.arch_sp -= self.bytesize
        self._emu.mem[self.regs.arch_sp] = value

    def stack_pop(self):
        sp = self.regs.arch_sp
        data = self[sp:sp + self.bytesize]
        self.regs.arch_sp += self.bytesize
        return data
    
    @staticmethod
    def _resolve_location(location: Union[int, str]):
        return location
