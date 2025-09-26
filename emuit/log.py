import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from emuit import EmuIt


class LevelBasedFormatter(logging.Formatter):
    FMT_INFO = "[%(name)s] %(message)s (%(name)s)"
    FMT_DEBUG = "[%(name)s][%(levelname)s][PC:%(current_pc)s] %(message)s (%(funcName)s)"

    def __init__(self, datefmt=None):
        super().__init__()
        self._fmt_info = logging.Formatter(self.FMT_INFO)
        self._fmt_debug = logging.Formatter(self.FMT_DEBUG)
    
    def format(self, record):
        if record.levelno == logging.INFO:
            return self._fmt_info.format(record)

        return self._fmt_debug.format(record)


def create_logger(emu: "EmuIt", level = logging.DEBUG):
    logger = logging.getLogger('EmuIt')
    logger.setLevel(level)

    old_factory = logging.getLogRecordFactory()
    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        record.current_pc = hex(emu.arch.regs.arch_pc) if hasattr(emu, '._arch') else 'undefined'
        return record
    logging.setLogRecordFactory(record_factory)

    formatter = LevelBasedFormatter()
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False

    return logger
