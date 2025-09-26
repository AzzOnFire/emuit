from emuit import EmuIt

import pytest


@pytest.fixture
def emuit_x8664() -> EmuIt:
    return EmuIt.create(architecture='x86', bitness=64)


def test_map_anywhere(emuit_x8664: EmuIt):
    size = 512
    buffer_ea = emuit_x8664.mem.map_anywhere(size)
    assert isinstance(buffer_ea, int)


def test_map(emuit_x8664: EmuIt):
    ea = 0x400000
    size = 512

    buffer_ea = emuit_x8664.mem.map(ea, size)
    assert buffer_ea == ea


def test_memory_write(emuit_x8664: EmuIt):
    size = 512
    data = b'A' * 100

    buffer_ea = emuit_x8664.mem.map_anywhere(size)
    emuit_x8664.mem[buffer_ea] = data

    assert data == emuit_x8664.mem[buffer_ea:buffer_ea + len(data)]


def test_outbound_write(emuit_x8664: EmuIt):
    ea = 0x400000

    with pytest.raises(Exception):
        _ = emuit_x8664.mem[ea:ea + 0x10]


def test_registry_write(emuit_x8664: EmuIt):
    emuit_x8664.arch.regs['EAX'] = 0x1000

    assert emuit_x8664.arch.regs['EAX'] == 0x1000


def test_registry_asterisk(emuit_x8664: EmuIt):
    emuit_x8664.arch.regs['*AX'] = 0xFFFF

    assert emuit_x8664.arch.regs['RAX'] == 0xFFFF


@pytest.mark.parametrize(
    "reg, reg_size",
    [('RAX', 8), ('EAX', 4), ('AX', 2), ('AH', 1), ('AL', 1)]
)
def test_registry_sizes(emuit_x8664: EmuIt, reg: str, reg_size: int):
    emuit_x8664.arch.regs[reg] = 0xFFFFFFFFFFFFFFFF

    assert emuit_x8664.arch.regs[reg] == 2 ** (reg_size * 8) - 1
