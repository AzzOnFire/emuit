from collections import UserDict
import string


class Result(UserDict):

    def range(self, start: int, end: int) -> "Result":
        return Result({k: v for k, v in self.items() if (start <= k <= end)})

    def printable(self) -> "Result":
        metrics = {self._printable_metric(v): k for k, v in self.items()}
        offset = metrics[max(metrics.keys())]

        return Result({offset: self[offset]})

    def pretty(self) -> "Result":
        return Result({offset: self._pretty(v) for offset, v in self.items()})

    @classmethod
    def _pretty(cls, data: bytes):
        result = ''

        if cls._unicode_metric(data) > 0.65:
            try:
                result = data.decode('UTF-16-LE')
            except UnicodeDecodeError:
                result = data.hex()
        else:
            result = data.decode(errors='replace')
    
        result = result.strip('\0') \
                        .encode('unicode_escape') \
                        .decode() \
                        .replace('\"', '\\"')

        return result

    @staticmethod
    def _unicode_metric(data: bytes):
        if len(data) < 2:
            return 0

        metric = 0
        for i, x in enumerate(data):
            if i & 1 and x == 0x00:
                metric += 1

        return metric / (len(data) / 2)
     
    @staticmethod
    def _printable_metric(data: bytes):
        printable = set(string.printable.encode())
        metric = sum([1.0 if x in printable else -1.0 for x in data])
        metric += sum([0.1 for x in data if x == 0x00])

        return (metric / len(data)) if metric > 0 else 0
