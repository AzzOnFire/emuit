import bisect
from collections import Counter, deque
import logging
from typing import Literal

import unicorn as uc

from .arch import EmuArch, EmuArchX86
from .memory import EmuMemory
from .log import create_logger
from .utils import Buffer


class EmuIt(object):
    MERGE_WRITE_ADDRESS_ACCURACY = 28
    RUN_ATTEMPTS = 16
    # Upper bounds for one run(), so code emulated with wrong inputs (e.g. a
    # garbage length or pointer) can't run or allocate memory forever.
    # None disables a limit.
    MAX_INSTRUCTIONS = 5_000_000
    MAX_FALLBACK_PAGES = 256  # blank pages mapped for writes outside known memory

    def __init__(self, uc_architecture: int, uc_mode: int):
        self._uc_architecture = uc_architecture
        self._uc_mode = uc_mode
        self._insn_trace: deque[int] = deque(maxlen=10)
        self._insn_count = 0
        self._insn_limit_hit = False
        self._fallback_pages = 0
        self._fallback_limit_hit = False
        self._write_sources: dict[int, int] = {}
        self._hooked_engine = None
        self._log = create_logger(self)
        self.reset()

    @property
    def log(self) -> logging.Logger:
        return self._log

    def reset(self):
        # 1. initialize Arch module
        if self._uc_architecture == uc.unicorn_const.UC_ARCH_X86:
            self._arch = EmuArchX86(self, self._uc_mode)
        else:
            self._arch = EmuArch(self, self._uc_architecture, self._uc_mode)

        # 2. initialize Memory (depends on Arch)
        self._mem = EmuMemory(self)

        # 3. initialize stack (depends on Memory)
        self._arch.stack_init()
        self.log.info('emulator was reset')

    @classmethod
    def create(
        cls,
        architecture: Literal[
            "x86", "arm", "mips", "ppc", "riscv", "s390", "tricore", "sparc", "m68k"
        ],
        bitness: Literal[16, 32, 64] = 64,
        endian: Literal["little", "big"] = "little",
    ):
        uc_architecture = {
            "x86": uc.unicorn_const.UC_ARCH_X86,
            "arm": (
                uc.unicorn_const.UC_ARCH_ARM
                if bitness == 32
                else (uc.unicorn_const.UC_ARCH_ARM64 if bitness == 64 else None)
            ),
            "mips": uc.unicorn_const.UC_ARCH_MIPS,
            "ppc": uc.unicorn_const.UC_ARCH_PPC,
            "riscv": uc.unicorn_const.UC_ARCH_RISCV,
            "s390": uc.unicorn_const.UC_ARCH_S390X,
            "tricore": uc.unicorn_const.UC_ARCH_TRICORE,
            "sparc": uc.unicorn_const.UC_ARCH_SPARC,
            "68k": uc.unicorn_const.UC_ARCH_M68K,
        }.get(architecture)

        if uc_architecture is None:
            raise ValueError("Unsupported architecture")

        uc_mode = 0
        if bitness == 16:
            uc_mode |= uc.unicorn_const.UC_MODE_16
        elif bitness == 32:
            uc_mode |= uc.unicorn_const.UC_MODE_32
        elif bitness == 64:
            uc_mode |= uc.unicorn_const.UC_MODE_64
        else:
            raise ValueError("Unsupported bitness")

        if endian == "little":
            uc_mode |= uc.unicorn_const.UC_MODE_LITTLE_ENDIAN
        elif endian == "big":
            uc_mode |= uc.unicorn_const.UC_MODE_BIG_ENDIAN
        else:
            raise ValueError("Unsupported endian")

        return cls(uc_architecture=uc_architecture, uc_mode=uc_mode)

    @property
    def mem(self) -> "EmuMemory":
        return self._mem

    @property
    def arch(self) -> "EmuArch":
        return self._arch

    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        if len(self.arch._unwind_stack):
            handler = self.arch._unwind_stack[0]  # pass from a function
            source = handler.pc
        else:
            source = self.arch.regs.arch_pc

        self._write_sources.update({address + offset: source for offset in range(0, size)})

    def _hook_mem_write_unmapped(self, uc, access, address, size, value, user_data):
        if not self._map_fallback_page(address):
            return False

        self._hook_mem_write(uc, access, address, size, value, user_data)

        return True

    def _map_fallback_page(self, address) -> bool:
        """Map a blank page for a write to memory nothing else provides.

        Limited to MAX_FALLBACK_PAGES per run(): past that, the write is left
        unmapped, so a runaway loop stops instead of mapping memory forever.
        """
        page = address & ~0xFFF
        if any(start <= page < end for start, end in self.mem.mapping):
            return True  # already mapped, e.g. by an earlier hook for this fault

        if self.MAX_FALLBACK_PAGES is not None and self._fallback_pages >= self.MAX_FALLBACK_PAGES:
            if not self._fallback_limit_hit:
                self._fallback_limit_hit = True
                self.log.warning(
                    f'not mapping more memory for writes outside known memory '
                    f'(limit: {self.MAX_FALLBACK_PAGES} pages per run, at 0x{address:0X})'
                )
            return False

        # map just the page holding the address: an unaligned
        # map(address, 0x1000) spans two pages
        self.mem.map(page, 0x1000)
        self._fallback_pages += 1
        return True

    def _hook_mem_read_unmapped(self, uc, access, address, size, value, user_data):
        return True

    def _hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        return False

    def _hook_code(self, uc, address, size, user_data):
        self._insn_trace.append(address)

        self._insn_count += 1
        if self.MAX_INSTRUCTIONS is not None and self._insn_count > self.MAX_INSTRUCTIONS:
            self._insn_limit_hit = True
            uc.emu_stop()

    def _hook_error(self, e):
        self.log.error(f'handle exception {e}')

    def run(self, start_ea: int, end_ea: int) -> list[Buffer]:
        # limits apply per run(), across all retry attempts
        self._insn_count = 0
        self._insn_limit_hit = False
        self._fallback_pages = 0
        self._fallback_limit_hit = False

        self._write_sources = {}
        self._add_hooks()

        for _ in range(self.RUN_ATTEMPTS):
            try:
                self.log.info(f'start emulation from 0x{start_ea:0X} to 0x{end_ea:0X}')
                self.arch.engine.emu_start(start_ea, end_ea)
                break
            except uc.UcError as e:
                if self._insn_limit_hit:
                    break
                prev_ea = self.arch.regs.arch_pc
                if not self._hook_error(e) or prev_ea == self.arch.regs.arch_pc:
                    break
                else:
                    start_ea = self.arch.regs.arch_pc

        if self._insn_limit_hit:
            self.log.warning(
                f'emulation stopped after {self.MAX_INSTRUCTIONS:,} instructions '
                f'(limit per run, at PC 0x{self.arch.regs.arch_pc:0X})'
            )

        return self._post_processing(self._write_sources)

    def _add_hooks(self):
        # Once per Unicorn engine (reset() creates a new one). Adding them on
        # every run() stacks them: each earlier run's hooks fire again, e.g.
        # counting every instruction once per run so far. Deleting them after
        # a run instead isn't safe: Unicorn's translated code can still call
        # a deleted hook, which crashes once Python frees its callback.
        engine = self.arch.engine
        if self._hooked_engine is engine:
            return
        engine.hook_add(uc.UC_HOOK_MEM_WRITE, self._hook_mem_write)
        engine.hook_add(uc.UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_mem_write_unmapped)
        engine.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED, self._hook_mem_read_unmapped)
        engine.hook_add(uc.UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_fetch_unmapped)
        engine.hook_add(uc.UC_HOOK_CODE, self._hook_code)
        self._hooked_engine = engine

    def _post_processing(self, entries: dict[int, int]) -> list[Buffer]:
        # The write hook records a write before Unicorn checks the address, so
        # writes that failed (e.g. past MAX_FALLBACK_PAGES) are recorded too:
        # keep only addresses that are mapped, as only those can be read.
        starts = [start for start, _ in self.mem.mapping]
        ends = [end for _, end in self.mem.mapping]

        def is_mapped(ea):
            i = bisect.bisect_right(starts, ea) - 1
            return i >= 0 and ea < ends[i]

        # chain contiguous memory addresses
        addresses = sorted(ea for ea in entries if is_mapped(ea))
        chains: Counter[int] = Counter()

        current_buffer_ea = 0
        for i, ea in enumerate(addresses):
            if (
                i == 0
                or addresses[i] != (addresses[i - 1] + 0x1)
                or abs(entries[ea] - entries[current_buffer_ea]) > self.MERGE_WRITE_ADDRESS_ACCURACY
            ):
                current_buffer_ea = ea
            chains[current_buffer_ea] += 1

        total = []
        for start_ea, size in chains.items():
            data = self.mem.read(start_ea, size)
            write_addresses = [
                entries.get(ea) for ea in range(start_ea, start_ea + size)
            ]
            buffer = Buffer(
                ea=start_ea,
                data=data,
                write_addresses=list(filter(None, write_addresses)),
            )
            total.append(buffer)

        return total
