import bisect
from typing import Union

import unicorn as uc


class EmuMemory(object):
    def __init__(self, engine: uc.Uc, ptr_size: int = 4):
        self.mapping: list[tuple[int, int]] = []
        self._ptr_size = ptr_size
        self._engine: uc.Uc = engine
        self._engine.ctl_get_mode()
        self.heap_min = 0x30000000  # after program segments
        self.heap_max = 0x70000000  # before system libraries

    def map_anywhere(self, size: int) -> int:
        return self.map(None, size)

    def map_buffer(self, buffer: bytes) -> int:
        ea = self.map(None, len(buffer))
        self.write(ea, buffer)
        return ea

    def map(self, address: int | None = None, size: int = 0x100) -> int:
        size = self.__align_high(size)
        if address is None:
            address = self.find_free_space(size)

        address = self.__align_low(address)

        return self._insert_block(address, size)

    def _insert_block(self, address: int, size: int, merge: bool = True):
        _start, _end = address, address + size

        to_delete = []
        for i, (start, end) in enumerate(self.mapping):
            if (
                (start <= _start and _end <= end)
                or (start <= _start < end)
                or (start < _end <= end)
            ):
                if merge:
                    _start = min(start, _start)
                    _end = max(end, _end)
                    to_delete.append(i)
                else:
                    raise ValueError(
                        f"Can't map 0x{_start:0X}-0x{_end:0X}: "
                        f"already allocated with 0x{start:0X}-0x{end:0X}"
                    )

        temp = {}
        for i in to_delete:
            start, end = self.mapping.pop(i)
            temp[start] = self.read(start, end - start)
            self._engine.mem_unmap(start, end - start)

        bisect.insort(self.mapping, (_start, _end))

        try:
            self._engine.mem_map(address, size)
        except Exception as e:
            print("Mapping error! Print map")
            for start, end in self.mapping:
                print(hex(start), "-", hex(end))
            raise e

        for (start, end), data in temp.items():
            self.write(start, data)

        return address

    def query(self, address: int) -> tuple[int, int] | None:
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

        raise ValueError(f"Can't unmap memory at 0x{address:0X}")

    def write(self, address: Union[str, int], data: Union[int, bytes]):
        address = int(address)
        if not isinstance(address, int):
            raise ValueError(
                f"Invalid address ({address}) specified for memory write destination"
            )

        if not self.query(address):
            raise ValueError(f"Write to unmapped memory at 0x{address:0X}")

        if isinstance(data, int):
            data = data.to_bytes(self._ptr_size, byteorder="little")

        return self._engine.mem_write(int(address), data)

    def read(self, address: Union[str, int], size: int) -> bytes:
        return bytes(self._engine.mem_read(address, size))

    def find_free_space(self, size):
        heap_segments = list(
            filter(
                lambda x: self.heap_min <= x[0] and x[1] <= self.heap_max,
                self.mapping,
            )
        )

        if not heap_segments:
            return self.heap_min

        # find free space between already allocated segments in heap
        prev_end = self.heap_min
        for i, (start, end) in enumerate(heap_segments):
            if start - self.__align_high(prev_end) > size:
                return self.__align_high(prev_end)

            prev_end = end

        # if still not found
        max_address = max(end for _, end in heap_segments)

        return self.__align_high(max_address)

    def __setitem__(self, key: Union[int, int], value: Union[int, bytes]):
        return self.write(key, value)

    def __getitem__(self, source: Union[int, slice]) -> bytes:
        if isinstance(source, slice):
            if source.step != 1 and source.step is not None:
                raise IndexError("step != 1 not supported")
            if source.start is None or source.stop is None:
                raise IndexError("range must be limited")

            length = source.stop - source.start
            return self.read(source.start, length)

        return self.read(source, self._ptr_size)

    @staticmethod
    def __align_low(value: int, border: int = 0x1000) -> int:
        return value & ~(border - 1)

    @staticmethod
    def __align_high(value: int, border: int = 0x1000) -> int:
        return (value + border - 1) & ~(border - 1)
