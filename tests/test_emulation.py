from emuit import EmuIt

import pytest


@pytest.fixture
def emuit_x8664() -> EmuIt:
    return EmuIt.create(architecture='x86', bitness=64)


@pytest.fixture
def emuit_x8632() -> EmuIt:
    return EmuIt.create(architecture='x86', bitness=32)


def test_stackstring(emuit_x8664: EmuIt):
    ea = 0x400000
    emuit_x8664.mem.map(ea, 0x1000)
    code = bytes.fromhex(
        "C7 00 5C 00 2A 00"         # mov dword ptr [rax], 2A005Ch
        "C7 40 04 2E 00 65 00"      # mov dword ptr [rax+4], 65002Eh
        "C7 40 08 78 00 65 00"      # mov dword ptr [rax+8], 650078h
    )

    emuit_x8664.mem[ea] = code

    results = emuit_x8664.run(ea, ea + len(code))
    assert any('\\*.exe' in x.try_decode() for x in results)


def test_simple(emuit_x8664: EmuIt):
    code = bytes.fromhex(
        "33 C0"     # xor eax, eax
    )

    buffer_ea = emuit_x8664.mem.map_buffer(code)

    emuit_x8664.arch.regs['EAX'] = 7
    assert emuit_x8664.arch.regs['EAX'] == 7
    emuit_x8664.run(buffer_ea, buffer_ea + 2)
    assert emuit_x8664.arch.regs['EAX'] == 0


# @pytest.mark.skip(reason="no way of currently testing this")
def test_decryption_stdcall(emuit_x8632: EmuIt):

    # .text:00011524  fn_Decryption proc near
    #                 arg_0         = dword ptr  8      key
    #                 arg_4         = dword ptr  0Ch    buffer
    #                 arg_8         = dword ptr  10h    length

    code = bytes.fromhex(
        "8B FF"                     # mov     edi, edi
        "55"                        # push    ebp
        "8B EC"                     # mov     ebp, esp
        "8B 55 0C"                  # mov     edx, [ebp+arg_4]
        "33 C0"                     # xor     eax, eax
        "3B D0"                     # cmp     edx, eax
        "74 2A"                     # jz      short loc_1155C
        "39 45 10"                  # cmp     [ebp+arg_8], eax
        "8B 4D 08"                  # mov     ecx, [ebp+arg_0]
        "76 22"                     # jbe     short loc_1155C
        "56"                        # push    esi
        "69 C9 0D 66 19 00"         # imul    ecx, 19660Dh
        "81 C1 5F F3 6E 3C"         # add     ecx, 3C6EF35Fh
        "8B F1"                     # mov     esi, ecx
        "C1 EE 10"                  # shr     esi, 10h
        "66 81 CE 00 80"            # or      si, 8000h
        "66 31 34 42"               # xor     [edx+eax*2], si
        "40"                        # inc     eax
        "3B 45 10"                  # cmp     eax, [ebp+arg_8]
        "72 E0"                     # jb      short loc_1153B
        "5E"                        # pop     esi
        "5D"                        # pop     ebp
        "C2 0C 00"                  # retn    0Ch
    )
    
    encrypted = bytes.fromhex(
        '58 B0 5E FC A2 F9 C9 BA E8 EE 47 AA 07 90 E5 99'
        '87 F2 C8 B0 7E D9 A1 C9 E5 8D B8 D4 00 00'
    )
    data = emuit_x8632.mem.map_buffer(encrypted)
    data_wlen = len(encrypted) // 2 - 1

    code_ea = emuit_x8632.mem.map_buffer(code)
    emuit_x8632.mem[code_ea] = code

    args = (0x1F2967E, data, data_wlen)
    results = emuit_x8632.arch.stdcall(code_ea, code_ea + len(code), *args)
    assert any('DosDevices' in x.try_decode() for x in results)
