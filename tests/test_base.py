from emuit import EmuItX86_64

import pytest


@pytest.fixture
def emuit_x64() -> EmuItX86_64:
    return EmuItX86_64(bitness=64)


def test_map_anywhere(emuit_x64: EmuItX86_64):
    size = 512
    buffer_ea = emuit_x64.malloc(size)
    assert isinstance(buffer_ea, int)


def test_malloc_ex(emuit_x64: EmuItX86_64):
    ea = 0x400000
    size = 512

    buffer_ea = emuit_x64.malloc_ex(ea, size)
    assert buffer_ea == ea


def test_memory_write(emuit_x64: EmuItX86_64):
    size = 512
    data = b'A' * 100

    buffer_ea = emuit_x64.malloc(size)
    emuit_x64[buffer_ea] = data

    assert data == emuit_x64[buffer_ea:buffer_ea + len(data)]


def test_outbound_write(emuit_x64: EmuItX86_64):
    ea = 0x400000

    with pytest.raises(Exception):
        _ = emuit_x64[ea:ea + 0x10]


def test_registry_write(emuit_x64: EmuItX86_64):
    emuit_x64['EAX'] = 0x1000

    assert emuit_x64['EAX'] == 0x1000


def test_registry_asterisk(emuit_x64: EmuItX86_64):
    emuit_x64['*AX'] = 0xFFFF

    assert emuit_x64['RAX'] == 0xFFFF


@pytest.mark.parametrize(
    "reg, reg_size",
    [('RAX', 8), ('EAX', 4), ('AX', 2), ('AH', 1), ('AL', 1)]
)
def test_registry_sizes(emuit_x64: EmuItX86_64, reg: str, reg_size: int):
    emuit_x64[reg] = 0xFFFFFFFFFFFFFFFF

    assert emuit_x64[reg] == 2 ** (reg_size * 8) - 1
