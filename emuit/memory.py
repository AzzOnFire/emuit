from typing import Union, Optional, Tuple

import unicorn as uc


class EmuMemory(object):
    def __init__(self, engine: uc.Uc, ptr_size: int = 4):
        self.mapping = []
        self._ptr_size = ptr_size
        self._engine: uc.Uc = _engine
        self._engine.ctl_get_mode()

    def map_anywhere(self, size: int) -> int:
        return self.map(None, size)

    def map(self, address: int = None, size: int = 0x100) -> int:
        size = align_high(size)
        if address is None:
            address = self.find_free_space(size)            
            block = (address, address + size)
            self._engine.mem_map(address, size)
            self.mapping.append(block)
            return address

        address = self.__align_low(address)
        block = (address, address + size)

        if not self.mapping:
            self._engine.mem_map(address, size)
            self.mapping.append(block)
            return address

        for i, (start, end) in enumerate(self.mapping):
            if start <= address and (address + size) <= end:
                raise ValueError(f'Can\'t map memory at 0x{address:0X}')

        self._engine.mem_map(address, size)
        self.mapping.insert(i, block)
        return address

    def query(self, address: int) -> Optional[Tuple[int, int]]:
        for _, (start, end) in enumerate(self.mapping):
            if start <= address <= end:
                return (start, end)

        return None

    def unmap(self, address: int) -> None:
        for i, (start, end) in enumerate(self.mapping):
            if start <= address <= end:
                self._engine.mem_unmap(start, end - start)
                del self.mapping[i]
                return

        raise ValueError(f'Can\'t unmap memory at 0x{address:0X}')

    def write(self, address: Union[str, int], data: Union[int, bytes]):
        address = int(address)
        if not isinstance(address, int):
            raise ValueError(f'Invalid address ({address}) specified for memory write destination')

        if not self.query(address):
            raise ValueError(f'Write to unmapped memory at 0x{address:0X}')

        if isinstance(value, int):
            value = value.to_bytes(self._ptr_size, byteorder='little')

        return self._engine.mem_write(int(address), value)

    def read(self, address: Union[str, int], size: int) -> bytes:
        return bytes(self.engine.mem_read(address, size))

    def find_free_space(self, size):
        if not self.mapping:
            return 0

        # find free space between already allocated segments
        prev_end = 0
        for i, (start, end) in enumerate(self.mapping):
            if start - self.__align_high(prev_end) > size:
                return self.__align_high(prev_end)
            
            prev_end = end

        # if still not found
        max_address = max(end for _, end in self.mapping)

        return self.__align_high(max_address)

    def __setitem__(self, key: Union[str, int], value: Union[int, bytes]):
        return self.write(key, value)

    def __getitem__(self, source: Union[str, slice]):

        if isinstance(source, slice):
            if source.step != 1 and source.step is not None:
                raise IndexError('step != 1 not supported')
            if source.start is None or source.stop is None:
                raise IndexError('range must be limited')

            length = source.stop - source.start
            return self.read(source.start, length)

    @staticmethod
    def __align_low(value: int, border: int = 4096):
        return (value // border) * border
    
    @staticmethod
    def __align_high(value: int, border: int = 4096):
        return (value // border + 1) * border
