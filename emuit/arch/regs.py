from typing import Union

from emuit import EmuIt

import unicorn as uc


class EmuRegs():
    arch_mapping = {
        uc.unicorn_const.UC_ARCH_ARM: 'ARM',
        uc.unicorn_const.UC_ARCH_ARM64: 'ARM64',
        uc.unicorn_const.UC_ARCH_MIPS: 'MIPS',
        uc.unicorn_const.UC_ARCH_X86: 'X86',
        uc.unicorn_const.UC_ARCH_PPC: 'PPC',
        uc.unicorn_const.UC_ARCH_SPARC: 'SPARC',
        uc.unicorn_const.UC_ARCH_M68K: 'M68K',
        uc.unicorn_const.UC_ARCH_RISCV: 'RISCV',
        uc.unicorn_const.UC_ARCH_S390X: 'S390X',
        uc.unicorn_const.UC_ARCH_TRICORE: 'TRICORE',
    }

    def __init__(self, emu: EmuIt):
        self._emu: EmuIt = emu

    @property
    def _pc_name(self) -> int:
        {
            uc.unicorn_const.UC_ARCH_ARM: uc.arm_const.UC_ARM_REG_PC,
            uc.unicorn_const.UC_ARCH_ARM64: uc.arm64_const.UC_ARM64_REG_PC,
            uc.unicorn_const.UC_ARCH_MIPS: uc.mips_const.UC_MIPS_REG_PC,
            uc.unicorn_const.UC_ARCH_X86: (
                uc.x86_const.UC_X86_REG_RIP if self._emu.uc_mode == uc.unicorn_const.UC_MODE_64 else (
                uc.x86_const.UC_X86_REG_EIP if self._emu.uc_mode == uc.unicorn_const.UC_MODE_32 else 
                uc.x86_const.UC_X86_REG_IP)
            ),
            uc.unicorn_const.UC_ARCH_PPC: uc.ppc_const.UC_PPC_REG_PC,
            uc.unicorn_const.UC_ARCH_SPARC: uc.sparc_const.UC_SPARC_REG_PC,
            uc.unicorn_const.UC_ARCH_M68K: uc.m68k_const.UC_M68K_REG_PC,
            uc.unicorn_const.UC_ARCH_RISCV: uc.riscv_const.UC_RISCV_REG_PC,
            uc.unicorn_const.UC_ARCH_S390X: uc.s390x_const.UC_S390X_REG_PC,
            uc.unicorn_const.UC_ARCH_TRICORE: uc.tricore_const.UC_TRICORE_REG_PC,
        }
    
    @property
    def _sp_name(self):
        {
            uc.unicorn_const.UC_ARCH_ARM: uc.arm_const.UC_ARM_REG_SP,
            uc.unicorn_const.UC_ARCH_ARM64: uc.arm64_const.UC_ARM64_REG_SP,
            uc.unicorn_const.UC_ARCH_MIPS: uc.mips_const.UC_MIPS_REG_SP,
            uc.unicorn_const.UC_ARCH_X86: (
                uc.x86_const.UC_X86_REG_RSP if self._emu.uc_mode == uc.unicorn_const.UC_MODE_64 else (
                uc.x86_const.UC_X86_REG_ESP if self._emu.uc_mode == uc.unicorn_const.UC_MODE_32 else 
                uc.x86_const.UC_X86_REG_SP)
            ),
            uc.unicorn_const.UC_ARCH_PPC: uc.ppc_const.UC_PPC_REG_1, # R1
            uc.unicorn_const.UC_ARCH_SPARC: uc.sparc_const.UC_SPARC_REG_SP,
            uc.unicorn_const.UC_ARCH_M68K: uc.m68k_const.UC_M68K_REG_A7,
            uc.unicorn_const.UC_ARCH_RISCV: uc.riscv_const.UC_RISCV_REG_SP,
            uc.unicorn_const.UC_ARCH_S390X: uc.s390x_const.UC_S390X_REG_R15,
            uc.unicorn_const.UC_ARCH_TRICORE: uc.tricore_const.UC_TRICORE_REG_SP,
        }[self._emu.uc_arch]
    
    @property
    def _bp_name(self):
        {
            # uc.arm_const.UC_ARCH_ARM: uc.arm_const.UC_ARM_REG_SP,
            # uc.arm64_const.UC_ARCH_ARM64: uc.arm64_const.UC_ARM64_REG_SP,
            uc.mips_const.UC_ARCH_MIPS: uc.mips_const.UC_MIPS_REG_FP,
            uc.x86_const.UC_ARCH_X86: (
                uc.x86_const.UC_X86_REG_RBP if self._emu.uc_mode == uc.x86_const.UC_MODE_64 else (
                uc.x86_const.UC_X86_REG_EBP if self._emu.uc_mode == uc.x86_const.UC_MODE_32 else 
                uc.x86_const.UC_X86_REG_BP)
            ),
            # uc.ppc_const.UC_ARCH_PPC: uc.ppc_const.UC_PPC_REG_1, # R1
            # uc.sparc_const.UC_ARCH_SPARC: uc.sparc_const.UC_SPARC_REG_SP,
            # uc.m68k_const.UC_ARCH_M68K: uc.m68k_const.UC_M68K_REG_A7,
            # uc.riscv_const.UC_ARCH_RISCV: uc.riscv_const.UC_RISCV_REG_SP,
            # uc.s390x_const.UC_ARCH_S390X: uc.s390x_const.UC_S390X_REG_R15,
            # uc.tricore_const.UC_ARCH_TRICORE: uc.tricore_const.UC_TRICORE_REG_SP,
        }[self._emu.uc_arch]
    
    def _reg_id_by_name(self, register: str):
        # bitness-neutral access for x86
        if self._emu.uc_arch == uc.x86_const.UC_ARCH_X86 and register.startswith('*'):
            register = 'R' if self.bitsize == 64 else 'E' + register[1:]
        # workaround for PPC arch
        elif self._emu.uc_arch == uc.x86_const.UC_ARCH_PPC and register.startswith('R'):
            register = register[1:]

        arch = self.arch_mapping[self._emu.uc_arch]
        module = getattr(uc, f'{arch.lower}_const')
        return getattr(module, f'UC_{arch.upper()}_REG_{register.upper()}')

    @property
    def arch_pc(self) -> int:
        return self._emu.engine.reg_read(self._pc_name)

    @arch_pc.setter
    def arch_pc(self, value: int) -> None:
        return self._emu.engine.reg_write(self._pc_name, value)

    @property
    def arch_sp(self) -> int:
        return self._emu.engine.reg_read(self._sp_name)

    @arch_sp.setter
    def arch_sp(self, value: int) -> None:
        return self._emu.engine.reg_write(self._sp_name, value)

    def __setitem__(
            self,
            destination: Union[str, int],
            value: int):

        value = self.parse_argument(value)
        reg_id = self._reg_id_by_name(destination)
        return self._emu.engine.reg_write(reg_id, value)

    def __getitem__(
            self,
            source: str):

        reg_id = self._reg_id_by_name(source)
        return self._emu.engine.reg_read(reg_id)
