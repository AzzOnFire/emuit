from emuit import EmuItX86_64

import pytest


@pytest.fixture
def emuit_x64() -> EmuItX86_64:
    return EmuItX86_64(bitness=64)


@pytest.fixture
def emuit_x86() -> EmuItX86_64:
    return EmuItX86_64(bitness=32)


def test_stackstring(emuit_x64: EmuItX86_64):
    ea = 0x400000
    code = bytes.fromhex(
        "C7 00 5C 00 2A 00"         # mov dword ptr [rax], 2A005Ch
        "C7 40 04 2E 00 65 00"      # mov dword ptr [rax+4], 65002Eh
        "C7 40 08 78 00 65 00"      # mov dword ptr [rax+8], 650078h
    )

    emuit_x64[ea] = code

    res = emuit_x64.run(ea, ea + len(code))
    print(res.pretty())
    assert any('\\*.exe' in x for x in res.pretty().values())


def test_simple(emuit_x64: EmuItX86_64):
    code = bytes.fromhex(
        "33 C0"     # xor eax, eax
    )

    buffer_ea = emuit_x64.malloc(0x100)
    emuit_x64[buffer_ea] = code

    emuit_x64['EAX'] = 7
    assert emuit_x64['EAX'] == 7
    emuit_x64.run(buffer_ea, buffer_ea + 2)
    assert emuit_x64['EAX'] == 0


# @pytest.mark.skip(reason="no way of currently testing this")
def test_decryption_stdcall(emuit_x86: EmuItX86_64):

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

    data = bytes.fromhex(
        '58 B0 5E FC A2 F9 C9 BA E8 EE 47 AA 07 90 E5 99'
        '87 F2 C8 B0 7E D9 A1 C9 E5 8D B8 D4 00 00'
    )
    data_wlen = 14

    start_ea, end_ea = 0x11524, 0x1155D
    _ = emuit_x86.malloc_ex(start_ea, end_ea - start_ea)
    emuit_x86[start_ea] = code

    args = (0x1F2967E, data, data_wlen)
    res = emuit_x86.stdcall(start_ea, end_ea, *args)
    assert any('DosDevices' in x for x in res.pretty().values())
