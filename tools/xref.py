import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

path = sys.argv[1]
targets = [int(t, 0) for t in sys.argv[2:]]

with open(path, 'rb') as f:
    elf = ELFFile(f)
    text = elf.get_section_by_name('.text')
    code = text.data()
    vend = text['sh_addr'] + len(code)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    insns = list(md.disasm(code, text['sh_addr']))

adrp = {}
for idx, ins in enumerate(insns):
    if ins.mnemonic == 'adrp':
        try:
            reg, imm = ins.op_str.split(', #')
            imm = int(imm, 0)
        except ValueError:
            continue
        base = imm
        adrp[(idx, reg.strip())] = base

for idx, ins in enumerate(insns):
    # adrp+add or adrp+ldr
    if ins.mnemonic in ('add', 'ldr') and '[x' not in ins.op_str:
        parts = ins.op_str.split(', ')
        if len(parts) >= 3 and parts[1].startswith('x'):
            src = parts[1].strip()
            key = (idx - 1, src)
            if key in adrp:
                try:
                    off = int(parts[2].lstrip('#'), 0)
                except ValueError:
                    continue
                addr = adrp[key] + off
                for t in targets:
                    if addr == t:
                        print(f"xref 0x{t:x} <- instr 0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")
