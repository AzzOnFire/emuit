import string
from statistics import mode


class Buffer(bytes):
    _ea: int
    _last_write_addresses: list[int]

    def __new__(cls, ea: int, data: bytes, write_addresses: list | None = None):
        instance = super().__new__(cls, data)
        instance._ea = ea
        instance._last_write_addresses = write_addresses or []
        return instance

    @property
    def ea(self) -> int:
        return self._ea

    @property
    def write_instruction_ea(self) -> int | None:
        addresses = [ea for ea in self._last_write_addresses if ea]
        if not addresses:
            return None  # mode() raises on an empty sequence

        return mode(addresses)

    def try_decode(self):
        result = ""

        data = bytes(self)
        if self.metric_unicode() > 0.65:
            if data.startswith(b'\x00'):
                data = data[1:]
            result = self.strip_until_decode(data, 'UTF-16-LE')
        else:
            result = self.strip_until_decode(data, 'UTF-8')

        result = (
            result.strip("\0").encode("unicode_escape").decode().replace('"', '\\"')
        )

        return result

    @staticmethod
    def strip_until_decode(data: bytes, encoding: str = 'UTF-8') -> str:
        """The longest prefix of `data` that decodes ('' if none does)."""
        try:
            return data.decode(encoding)
        except UnicodeDecodeError as e:
            # Everything before the first error decodes. Dropping one byte at
            # a time from the end instead took quadratic time, and returned
            # None when nothing decoded.
            return data[:e.start].decode(encoding)

    def metric_unicode(self):
        if len(self) < 2:
            return 0

        # Compare the two bytes of each UTF-16 code unit. Pairing self[i - 1]
        # with self[i] instead made the first pair (self[-1], self[0]) wrap
        # around, so e.g. b'D\x00S\x00\x00\x00\x00' wasn't seen as UTF-16.
        metric = 0
        for i in range(0, len(self) - 1, 2):
            if self[i] != 0x00 and self[i + 1] == 0x00:
                metric += 1  # UTF-16-LE: low byte, then 0
            elif self[i] == 0x00 and self[i + 1] != 0x00:
                metric -= 1  # the same, shifted by one byte

        return abs(metric) / (len(self) // 2)

    def metric_decodable(self) -> float:
        if len(self) < 2:
            return 0

        printable = set(string.printable.encode())
        unicode_metric = self.metric_unicode()
        metric = 0.0
        for x in self:
            if x in printable:
                metric += 1.0
            elif x == 0x00:
                metric += unicode_metric ** 2
            else:
                metric -= 1.0

        return (metric / len(self)) if metric > 0 else 0

    def __repr__(self):
        pc = self.write_instruction_ea
        pc = 'None' if pc is None else f'0x{pc:X}'
        return f'Buffer(pc={pc}, ea=0x{self.ea:X}, data={bytes(self)!r})'
