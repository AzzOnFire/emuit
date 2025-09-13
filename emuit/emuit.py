from abc import abstractmethod
from collections import Counter
from typing import TYPE_CHECKING, Union, Optional, Tuple

from .arch import EmuArch, EmuArchX86
from .memory import EmuMemory
from .result import Result

import unicorn as uc


class EmuIt(object):
    def __init__(self, uc_architecture: int, uc_mode: int):
        self._arch: EmuArch = None
        
        if uc_architecture == uc.unicorn_const.UC_ARCH_X86:
            self._arch = EmuArchX86(self, uc_mode)
        else:
            self._arch = EmuArch(self, uc_architecture, uc_mode)

        self._mem = EmuMemory(self.arch.engine, ptr_size=self.arch.bytesize)

        self.reset()
    
    @property
    def mem(self) -> EmuMemory:
        return self._mem

    @property
    def arch(self) -> EmuArch:
        return self._arch

    def reset(self):
        pass

    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        user_data.update([address + offset for offset in range(0, size)])

    def _hook_mem_invalid_write(self, uc, access, address, size, value, user_data):
        self.mem.map(address, 64 * 1024)
        user_data.update([address + offset for offset in range(0, size)])
        return True

    def _hook_mem_fetch_unmapped(self, uc, access, address, size, value, data):
        return False

    def _hook_code(self, uc, address, size, user_data):
        # print(hex(address), size)
        pass

    def run(self, start_ea: int, end_ea: int) -> Result:
        user_data = set()
        self.arch.engine.hook_add(uc.UC_HOOK_MEM_WRITE,
                         self._hook_mem_write,
                         user_data)
        self.arch.engine.hook_add(uc.UC_HOOK_MEM_WRITE_UNMAPPED,
                         self._hook_mem_invalid_write,
                         user_data)
        self.arch.engine.hook_add(uc.UC_HOOK_MEM_FETCH_UNMAPPED, 
                         self._hook_mem_fetch_unmapped)
        self.arch.engine.hook_add(uc.UC_HOOK_CODE,
                        self._hook_code,
                        aux1=uc.x86_const.UC_X86_INS_CALL)

        try:
            self.arch.engine.emu_start(start_ea, end_ea)
        except uc.UcError as e:
            print('EmuIt Error:', e)

        return self._post_processing(user_data)

    def _post_processing(self, entries: set) -> Result:
        addresses = sorted(entries)
        chains = Counter()

        for i, ea in enumerate(addresses):
            if i == 0 or addresses[i] != (addresses[i - 1] + 0x1):
                current_buffer_ea = ea
            chains[current_buffer_ea] += 1

        data = {ea: self.mem[ea:ea + size] for ea, size in chains.items()}
        return Result(data)
