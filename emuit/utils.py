import string
from statistics import mode


class Buffer(bytes):
    def __new__(cls, ea: int, data: bytes, write_addresses: list):
        instance = super().__new__(cls, data)
        instance._ea = ea
        instance._last_write_addresses = write_addresses
        return instance

    @property
    def ea(self) -> int:
        return self._ea

    @property
    def write_instruction_ea(self) -> int:
        return mode(filter(None, self._last_write_addresses))

    def try_decode(self):
        result = ''

        if self.metric_unicode() > 0.65:
            try:
                result = self.decode('UTF-16-LE')
            except UnicodeDecodeError:
                result = self.hex()
        else:
            result = self.decode(errors='replace')
    
        result = result.strip('\0') \
                        .encode('unicode_escape') \
                        .decode() \
                        .replace('\"', '\\"')

        return result

    def metric_unicode(self):
        if len(self) < 2:
            return 0

        metric = 0
        for i, x in enumerate(self):
            if i & 1 and x == 0x00:
                metric += 1

        return metric / (len(self) / 2)
     
    def metric_printable(self) -> float:
        printable = set(string.printable.encode())
        metric = sum([1.0 if x in printable else -1.0 for x in self])
        metric += sum([0.1 for x in self if x == 0x00])

        return (metric / len(self)) if metric > 0 else 0
