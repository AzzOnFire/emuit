import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from emuit import EmuIt


class LevelBasedFormatter(logging.Formatter):
    FMT_INFO = "[%(name)s] %(message)s"
    FMT_ERROR = "[%(name)s] %(message)s (PC:%(current_pc)s)"

    def __init__(self, datefmt=None):
        super().__init__()
        self._fmt_info = logging.Formatter(self.FMT_INFO)
        self._fmt_error = logging.Formatter(self.FMT_ERROR)
    
    def format(self, record):
        if record.levelno in {logging.INFO, logging.DEBUG}:
            return self._fmt_info.format(record)

        return self._fmt_error.format(record)


def create_logger(emu: "EmuIt", level = logging.DEBUG):
    logger = logging.getLogger('EmuIt')
    logger.setLevel(level)

    old_factory = logging.getLogRecordFactory()
    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        record.current_pc = f'0x{emu.arch.regs.arch_pc:0X}' if hasattr(emu, '_arch') else 'undefined'
        return record
    logging.setLogRecordFactory(record_factory)

    formatter = LevelBasedFormatter()
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False

    return logger
