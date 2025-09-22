from collections import Counter, deque
from typing import TYPE_CHECKING, Literal

from .regs import EmuRegs
if TYPE_CHECKING:
    from emuit import EmuIt

import unicorn as uc


class EmuArch(object):
    UNWIND_MAX_ATTEMPTS = 5

    def __init__(self, emu: "EmuIt", uc_architecture: int, uc_mode: int):
        self._emu: "EmuIt" = emu
        self._uc_mode = uc_mode
        self._uc_architecture = uc_architecture
        self._engine = uc.Uc(uc_architecture, uc_mode)
        self._regs: EmuRegs = EmuRegs(self)
        self._unwind_stats: Counter[int] = Counter()
        self._unwind_stack: deque[tuple[int, int]] = deque()
    
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

    def add_unwind_record(self, return_ea: int, sp_value: int):
        print('checking call stack')
        while len(self._unwind_stack):
            pc, record_sp = self._unwind_stack[-1]
            print('tr SP:', hex(sp_value), 'stored SP:', hex(record_sp))
            if sp_value < record_sp:
                break

            self._unwind_stack.pop()

        print('add PC:', hex(return_ea), 'SP:', hex(sp_value))
        self._unwind_stack.append((return_ea, sp_value))
    
    def unwind(self):
        print('Call stack', self._unwind_stack)
        while len(self._unwind_stack):
            pc, sp = self._unwind_stack.pop()
            print('Extract from call stack', hex(pc), hex(sp))

            if self.regs.arch_sp < sp:
                self._unwind_stats[pc] += 1
                if self._unwind_stats[pc] > self.UNWIND_MAX_ATTEMPTS:
                    print('Maximum count of attempts reached at', hex(pc))
                    continue

                print('Unwind to', hex(pc), hex(sp))
                self.regs.arch_pc = pc
                self.regs.arch_sp = sp
                return
