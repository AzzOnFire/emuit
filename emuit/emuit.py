from collections import Counter, deque
from typing import Literal

import unicorn as uc

from .arch import EmuArch, EmuArchX86
from .memory import EmuMemory
from .utils import Buffer


class EmuIt(object):
    def __init__(self, uc_architecture: int, uc_mode: int):
        self._uc_architecture = uc_architecture
        self._uc_mode = uc_mode
        self._insn_trace: deque[int] = deque(maxlen=10)
        self.reset()

    def reset(self):
        if self._uc_architecture == uc.unicorn_const.UC_ARCH_X86:
            self._arch = EmuArchX86(self, self._uc_mode)
        else:
            self._arch = EmuArch(self, self._uc_architecture, self._uc_mode)

        self._mem = EmuMemory(self.arch.engine, ptr_size=self.arch.ptr_size)

        stack_size = 1 * 1024 * 1024    # 1 MB
        stack_base = self._mem.map_anywhere(stack_size)
        self._arch.regs.arch_sp = stack_base + (stack_size // 2) & ~0xFF

    @classmethod
    def create(
        cls,
        architecture: Literal['x86', 'arm', 'mips', 'ppc', 'riscv', 's390', 'tricore', 'sparc', 'm68k'],
        bitness: Literal[16, 32, 64] = 64,
        endian: Literal['little', 'big'] = 'little'
    ):
        uc_architecture = {
            'x86': uc.unicorn_const.UC_ARCH_X86,
            'arm': (
                uc.unicorn_const.UC_ARCH_ARM if bitness == 32
                else (uc.unicorn_const.UC_ARCH_ARM64 if bitness == 64
                      else None
                      )),
            'mips': uc.unicorn_const.UC_ARCH_MIPS,
            'ppc': uc.unicorn_const.UC_ARCH_PPC,
            'riscv': uc.unicorn_const.UC_ARCH_RISCV,
            's390': uc.unicorn_const.UC_ARCH_S390X,
            'tricore': uc.unicorn_const.UC_ARCH_TRICORE,
            'sparc': uc.unicorn_const.UC_ARCH_SPARC,
            '68k': uc.unicorn_const.UC_ARCH_M68K,
        }.get(architecture)

        if uc_architecture is None:
            raise ValueError('Unsupported architecture')

        uc_mode = 0
        if bitness == 16:
            uc_mode |= uc.unicorn_const.UC_MODE_16
        elif bitness == 32:
            uc_mode |= uc.unicorn_const.UC_MODE_32
        elif bitness == 64:
            uc_mode |= uc.unicorn_const.UC_MODE_64
        else:
            raise ValueError('Unsupported bitness')

        if endian == 'little':
            uc_mode |= uc.unicorn_const.UC_MODE_LITTLE_ENDIAN
        elif endian == 'big':
            uc_mode |= uc.unicorn_const.UC_MODE_BIG_ENDIAN
        else:
            raise ValueError('Unsupported endian')

        return cls(uc_architecture=uc_architecture, uc_mode=uc_mode)

    @property
    def mem(self) -> "EmuMemory":
        return self._mem

    @property
    def arch(self) -> "EmuArch":
        return self._arch

    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        if len(self.arch._unwind_stack):
            source, _ = self.arch._unwind_stack[0]
        else:
            source = self.arch.regs.arch_pc

        user_data.update({
            address + offset: source
            for offset in range(0, size)
        })

    def _hook_mem_write_unmapped(self, uc, access, address, size, value, user_data):
        self.mem.map(address, 0x1000)
        self._hook_mem_write(user_data, address, size)

        return True

    def _hook_mem_read_unmapped(self, uc, access, address, size, value, user_data):
        return True

    def _hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        return False

    def _hook_code(self, uc, address, size, user_data):
        self._insn_trace.append(address)

    def _hook_error(self, e):
        print('EmuIt Error:', e)

    def run(self, start_ea: int, end_ea: int) -> list[Buffer]:
        user_data: dict[int, int] = {}
        self.arch.engine.hook_add(uc.UC_HOOK_MEM_WRITE,
                                  self._hook_mem_write,
                                  user_data)
        self.arch.engine.hook_add(uc.UC_HOOK_MEM_WRITE_UNMAPPED,
                                  self._hook_mem_write_unmapped,
                                  user_data)
        self.arch.engine.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED,
                                  self._hook_mem_read_unmapped)
        self.arch.engine.hook_add(uc.UC_HOOK_MEM_FETCH_UNMAPPED,
                                  self._hook_mem_fetch_unmapped)
        self.arch.engine.hook_add(uc.UC_HOOK_CODE,
                                  self._hook_code,
                                  aux1=uc.x86_const.UC_X86_INS_CALL)

        for _ in range(16):
            try:
                print('Start emulation from', hex(start_ea), 'to', hex(end_ea))
                self.arch.engine.emu_start(start_ea, end_ea)
                break
            except uc.UcError as e:
                if not self._hook_error(e):
                    break
                else:
                    start_ea = self.arch.regs.arch_pc
                    print('Unwinding to', hex(start_ea))

        return self._post_processing(user_data)

    def _post_processing(self, entries: dict[int, int]) -> list[Buffer]:
        # chain contiguous memory addresses
        addresses = sorted(entries.keys())
        chains: Counter[int] = Counter()

        current_buffer_ea = 0
        for i, ea in enumerate(addresses):
            if i == 0 or addresses[i] != (addresses[i - 1] + 0x1) or entries[ea] != entries[current_buffer_ea]:
                current_buffer_ea = ea
            chains[current_buffer_ea] += 1

        total = []
        for start_ea, size in chains.items():
            data = self.mem.read(start_ea, size)
            write_addresses = [entries.get(ea) for ea in range(start_ea, start_ea + size)]
            buffer = Buffer(ea=start_ea, data=data, write_addresses=list(filter(None, write_addresses)))
            total.append(buffer)

        return total
