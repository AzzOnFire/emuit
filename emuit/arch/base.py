from abc import ABC, abstractmethod
from collections import Counter
from typing import Union, Optional, Tuple

from .result import Result
from .memory import EmuItMemory
from emuit import EmuIt

import unicorn as uc


class EmuArch(ABC):
    def __init__(self, emu: EmuIt):
        self._emu: EmuIt = emu

    @abstractmethod
    def _reg_parse(register: str):
        raise NotImplementedError('Implement _reg_parse')

    def __setitem__(
            self,
            destination: Union[str, int],
            value: Union[int, str, bytes]):

        value = self.parse_argument(value)
        reg_id = self._reg_parse(destination)
        return self._emu.engine.reg_write(reg_id, value)

    def __getitem__(
            self,
            source: str):

        reg_id = self._reg_parse(source)
        return self._emu.engine.reg_read(reg_id)

    def stack_push(self, value: Union[int, str, bytes]):
        self['*SP'] -= self.bytesize
        self[self['*SP']] = value

    def stack_pop(self):
        sp = self['*SP']
        data = self[sp:sp + self.bytesize]
        self['*SP'] += self.bytesize
        return data