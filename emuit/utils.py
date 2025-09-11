import idaapi
import ida_ida

import unicorn as uc


class IdaUcUtils(object):
    @staticmethod
    def get_uc_bitness() -> int:
        ida_version = tuple(map(int, idaapi.get_kernel_version().split(".")))
        if ida_version >= (9, 0):
            if ida_ida.inf_is_64bit():
                return uc.unicorn_const.UC_MODE_64
            elif ida_ida.inf_is_32bit_exactly():
                return uc.unicorn_const.UC_MODE_32
            elif ida_ida.inf_is_16bit():
                return uc.unicorn_const.UC_MODE_16
            else:
                raise ValueError('Unknown architecture bitness')
        else:
            info = idaapi.get_inf_structure()
            if info.is_64bit():
                return uc.unicorn_const.UC_MODE_64
            elif info.is_32bit():
                return uc.unicorn_const.UC_MODE_32
            else:
                return uc.unicorn_const.UC_MODE_16

    @staticmethod
    def get_processor_name() -> str:
        ida_version = tuple(map(int, idaapi.get_kernel_version().split(".")))
        if ida_version >= (9, 0):
            return ida_ida.inf_get_procname()
        else:
            info = idaapi.get_inf_structure()
            return info.procname.lower()

    @staticmethod
    def is_big_endian() -> bool:
        ida_version = tuple(map(int, idaapi.get_kernel_version().split(".")))
        if ida_version >= (9, 0):
            return ida_ida.inf_is_be()
        else:
            info = idaapi.get_inf_structure()
            return info.is_be()

    @classmethod
    def get_uc_arch_mode(cls):
        proc = cls.get_processor_name()
        mode = cls.get_uc_bitness()
        if proc == "metapc": 
            arch = uc.unicorn_const.UC_ARCH_X86
        elif "arm" in proc:
            arch = uc.unicorn_const.UC_ARCH_ARM64 if mode == uc.unicorn_const.UC_MODE_64 else uc.unicorn_const.UC_ARCH_ARM
        elif "mips" in proc:    # mipsb, mipsl
            mode |= uc.unicorn_const.UC_MODE_BIG_ENDIAN if 'mispb' in proc else uc.unicorn_const.UC_MODE_LITTLE_ENDIAN
            arch = uc.unicorn_const.UC_ARCH_MIPS
        elif "ppc" in proc:     # ppc, ppcl
            mode |= uc.unicorn_const.UC_MODE_LITTLE_ENDIAN if 'ppcl' in proc else uc.unicorn_const.UC_MODE_BIG_ENDIAN
            arch = uc.unicorn_const.UC_ARCH_PPC
        elif "riscv" in proc:
            arch = uc.unicorn_const.UC_ARCH_RISCV
        elif "s390" in proc:    # s390 - 32bit, s390x - 64bit
            arch = uc.unicorn_const.UC_ARCH_S390X   
        elif "tricore" in proc:
            arch = uc.unicorn_const.UC_ARCH_TRICORE
        elif "sparc" in proc:   # sparcb sparcl
            mode |= uc.unicorn_const.UC_MODE_BIG_ENDIAN if 'sparcb' in proc else uc.unicorn_const.UC_MODE_LITTLE_ENDIAN
            arch = uc.unicorn_const.UC_ARCH_SPARC   
        elif "68k" in proc:
            arch = uc.unicorn_const.UC_ARCH_M68K

        return arch, mode
