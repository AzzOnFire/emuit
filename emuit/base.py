from abc import abstractmethod
from collections import Counter
from typing import Union, Optional, Tuple

from .result import Result

import unicorn as uc


class EmuIt(object):
    def __init__(self, arch, mode, bitness: int):
        self.bitsize = bitness
        self.bytesize = bitness // 8
        self.mu = uc.Uc(arch, mode)
        self.mapping = []
        self.reset()

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

    @abstractmethod
    def _reg_parse(register: str):
        raise NotImplementedError('Implement _reg_parse')

    def __setitem__(
            self,
            destination: Union[str, int],
            value: Union[int, str, bytes]):

        value = self.parse_argument(value)
        if isinstance(destination, int):
            if isinstance(value, int):
                value = value.to_bytes(self.bytesize, byteorder='little')

            if not self.query(destination):
                self.malloc_ex(destination, len(value))

            return self.mu.mem_write(destination, value)

        if isinstance(value, bytes):
            buffer = self.malloc(len(value))
            self.mu.mem_write(buffer, value)
            value = buffer

        reg_id = self._reg_parse(destination)
        return self.mu.reg_write(reg_id, value)

    def __getitem__(
            self,
            source: Union[str, slice]):

        if isinstance(source, slice):
            if source.step != 1 and source.step is not None:
                raise IndexError('step != 1 not supported')
            if source.start is None or source.stop is None:
                raise IndexError('range must be limited')

            length = source.stop - source.start
            return bytes(self.mu.mem_read(source.start, length))

        reg_id = self._reg_parse(source)
        return self.mu.reg_read(reg_id)

    def malloc(self, size: int) -> int:
        return self.malloc_ex(None, size)

    def malloc_ex(self, address: int = None, size: int = 0x100) -> int:
        def align_low(value: int, border: int = 4096):
            return (value // border) * border
        
        def align_high(value: int, border: int = 4096):
            return (value // border + 1) * border
        
        size = align_high(size)
        if address is None:
            if self.mapping:
                max_address = max(end for _, end in self.mapping)
            else:
                max_address = 0

            address = align_high(max_address)
            block = (address, address + size)
            self.mu.mem_map(address, size)
            self.mapping.append(block)
            return address

        address = align_low(address)
        block = (address, address + size)

        if not self.mapping:
            self.mu.mem_map(address, size)
            self.mapping.append(block)
            return address

        for i, (start, end) in enumerate(self.mapping):
            if start <= address and (address + size) <= end:
                raise ValueError(f'Can\'t allocate memory at {address:0X}')

        self.mu.mem_map(address, size)
        self.mapping.insert(i, block)
        return address

    def query(self, address: int) -> Optional[Tuple[int, int]]:
        for _, (start, end) in enumerate(self.mapping):
            if start <= address <= end:
                return (start, end)

        return None

    def free(self, address: int) -> None:
        for _, (start, end) in enumerate(self.mapping):
            if start <= address <= end:
                self.mu.mem_unmap(start, end - start)
                return

        raise ValueError(f'Can\'t free memory at {address:0X}')

    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        user_data.update([address + offset for offset in range(0, size)])

    def _hook_mem_invalid_write(self, uc, access, address, size, value, user_data):
        self.malloc_ex(address, 64 * 1024)
        user_data.update([address + offset for offset in range(0, size)])
        return True

    def _hook_code(self, uc, address, size, user_data):
        # print(hex(address), size)
        pass

    def run(self, start_ea: int, end_ea: int) -> Result:
        user_data = set()
        self.mu.hook_add(uc.UC_HOOK_MEM_WRITE,
                         self._hook_mem_write,
                         user_data)
        self.mu.hook_add(uc.UC_HOOK_MEM_WRITE_UNMAPPED,
                         self._hook_mem_invalid_write,
                         user_data)

        # FIXME workaround for latest unicorn versions
        try:
            self.mu.hook_add(uc.UC_HOOK_CODE,
                            self._hook_code,
                            aux1=uc.x86_const.UC_X86_INS_CALL)
        except TypeError:

            self.mu.hook_add(uc.UC_HOOK_CODE,
                            self._hook_code,
                            arg1=uc.x86_const.UC_X86_INS_CALL)

        try:
            self.mu.emu_start(start_ea, end_ea)
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
