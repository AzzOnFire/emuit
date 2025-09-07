from abc import abstractmethod
from collections import Counter
from typing import TYPE_CHECKING, Union, Optional, Tuple

# See https://stackoverflow.com/questions/39740632/python-type-hinting-without-cyclic-imports
if TYPE_CHECKING:
    from .arch.base import QlArch
    from .os.memory import QlMemoryManager


from .result import Result
from .arch import EmuArchBase
from .memory import EmuMemory

import unicorn as uc


class EmuIt(object):
    def __init__(self, arch, mode, bitness: int):
        self.bitsize = bitness
        self.bytesize = bitness // 8
        self.engine = uc.Uc(arch, mode)
        self._mem = EmuMemory(self.engine, ptr_size=(bitness // 8))
        self.reset()

    @property
    def mem(self) -> EmuMemory:
        return self._mem

    def reset(self):
        pass

    def parse_argument(self, value: Union[int, str, bytes]):
        if isinstance(value, int):
            max_length = self.bitsize
            if value.bit_length() > max_length:
                raise ValueError(f'Value {value} is out of {max_length} bits')

            return value

        if isinstance(value, str):
            return value.encode('ascii')

        return value

    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        user_data.update([address + offset for offset in range(0, size)])

    def _hook_mem_invalid_write(self, uc, access, address, size, value, user_data):
        self.malloc_ex(address, 64 * 1024)
        user_data.update([address + offset for offset in range(0, size)])
        return True

    def _hook_unmapped(self, uc, access, address, size, value, data):
        return False

    def _hook_code(self, uc, address, size, user_data):
        # print(hex(address), size)
        pass

    def run(self, start_ea: int, end_ea: int) -> Result:
        user_data = set()
        self.engine.hook_add(uc.UC_HOOK_MEM_WRITE,
                         self._hook_mem_write,
                         user_data)
        self.engine.hook_add(uc.UC_HOOK_MEM_WRITE_UNMAPPED,
                         self._hook_mem_invalid_write,
                         user_data)
        self.engine.hook_add(uc.UC_HOOK_MEM_FETCH_UNMAPPED, 
                         self._hook_unmapped)
        self.engine.hook_add(uc.UC_HOOK_CODE,
                        self._hook_code,
                        aux1=uc.x86_const.UC_X86_INS_CALL)

        try:
            self.engine.emu_start(start_ea, end_ea)
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

        data = {ea: self[ea:ea + size] for ea, size in chains.items()}
        return Result(data)
