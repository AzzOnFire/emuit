from collections import Counter, deque
from typing import TYPE_CHECKING, Literal
from dataclasses import dataclass

from .regs import EmuRegs
if TYPE_CHECKING:
    from emuit import EmuIt

import unicorn as uc


@dataclass(frozen=True)
class UnwindHandler():
    pc: int
    sp: int
    label: str

    def __repr__(self):
        return f"UnwindHandler(pc=0x{self.pc:0X}, sp=0x{self.sp:0X}, label={self.label})"


class EmuArch(object):
    UNWIND_MAX_ATTEMPTS = 5

    def __init__(self, emu: "EmuIt", uc_architecture: int, uc_mode: int):
        self._emu: "EmuIt" = emu
        self._uc_mode = uc_mode
        self._uc_architecture = uc_architecture
        self._engine = uc.Uc(uc_architecture, uc_mode)
        self._regs: EmuRegs = EmuRegs(self)
        self._unwind_stats: Counter[int] = Counter()
        self._unwind_stack: deque[UnwindHandler] = deque()

    @property
    def log(self):
        return self._emu.log

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
        data: bytes = self._emu.mem.read(self.regs.arch_sp, self.ptr_size)
        self.regs.arch_sp += self.ptr_size
        return int.from_bytes(data, byteorder=self.endian)

    def add_unwind_record(self, return_ea: int, sp_value: int, label: str = ''):
        while len(self._unwind_stack):
            # Remove previous unwind handlers
            handler = self._unwind_stack[-1]
            if sp_value < handler.sp:
                break

            self._unwind_stack.pop()

        new_handler = UnwindHandler(return_ea, sp_value, label)
        self.log.debug(f'add handler: {new_handler}')
        self._unwind_stack.append(new_handler)
    
    def unwind(self):
        while len(self._unwind_stack):
            handler = self._unwind_stack.pop()
            self.log.debug(f'next handler: {handler}')

            if self.regs.arch_sp < handler.sp:
                self._unwind_stats[handler.pc] += 1
                if self._unwind_stats[handler.pc] > self.UNWIND_MAX_ATTEMPTS:
                    self.log.warning(f'maximum count of unwind attempts reached ({self.UNWIND_MAX_ATTEMPTS})')
                    continue

                self.log.info(f'unwind to IP=0x{handler.pc:0X} ({handler.label}), SP=0x{handler.sp:0X}')
                self.regs.arch_pc = handler.pc
                self.regs.arch_sp = handler.sp
                return True
        return False

    def stack_init(self, size: int = 1 * 1024 * 1024):
        base = self._emu.mem.map_anywhere(size)
        self.log.debug(f'stack allocated at 0x{base:0X}')
        self.regs.arch_sp = base + (size // 2) & ~0xFF
