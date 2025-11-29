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
        if self._last_write_addresses is None:
            return None

        return mode(filter(None, self._last_write_addresses))

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
    def strip_until_decode(data: bytes, encoding: str = 'UTF-8'):
        while len(data):
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                data = data[:-1]

    def metric_unicode(self):
        if len(self) < 2:
            return 0

        metric = 0
        for i in range(0, len(self), 2):
            if self[i - 1] == 0x00 and self[i] != 0x00:
                metric += 1
            elif self[i - 1] != 0x00 and self[i] == 0x00:
                metric -= 1

        return abs(metric) / (len(self) / 2)

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
            print(x, metric, (metric / len(self)) if metric > 0 else 0)
        
        return (metric / len(self)) if metric > 0 else 0

    def __repr__(self):
        return f'Buffer(pc=0x{self.write_instruction_ea:0X}, ea=0x{self.ea}, data={self!r})'