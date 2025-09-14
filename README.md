## EmuIt - easy-to-use IDA emulator plugin

### Use cases
- Run code without starting debug session (broken dump, driver, firmware...)
- Find decryption function in malware and get all decrypted strings 
- Automate process of config extraction

### Quick example
![QuickExample](./images/example.png)

### Installation
Copy `emuit.py` and `emuit` directory to `plugins` directory in `%IDA_HOME%` or `%IDA_USER%`

### Examples
```python
from emuit import EmuIt
emu = EmuIt.create(architecture='x86', bitness=64)
```

Memory and registers manipulations:
```python
buffer = emu.mem[0x400000:0x401000]  # read memory region
emu.mem[0x1002F0C8:] = b"string"       # write string at address

ip = emu.arch.regs.arch_pc         # get RIP value
emu.arch.regs['RDX'] = 0xABCDEF   # access by register name
emu.arch.regs['*DX'] = 0xABCDEF   # asterisk mean 'R' for x64 or 'E' for x86

emu.arch.stack_push(0xABCDEF)      # push value to stack
value = emu.arch.stack_pop()
```

Emulate arbitrary code chunk:
```python
result = emu.run(0x100000, 0x100020)
print(result)   # has helper methods `pretty`, `range`, `printable`
>>> {0x3000: 'decrypted string...', 0x24000: 'stack junk...', ...}
```

Call function:
```python
start_ea, end_ea = 0x10021050, 0x10023010 
emu.arch.fastcall(
    start_ea,
    end_ea, 
    rcx=emu.mem.map_buffer(b'string!'),
    rdx=0x6,
)
```

### Limitations
- Emulate code with API calls, syscalls
- Access to internal structures (PEB, SEH, ...)

### TODO

- (?) partial PEB emulation to deal with malware API resolve by hash
- Instruction tracing with detailed error report
