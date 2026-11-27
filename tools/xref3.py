import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

path = sys.argv[1]
target = int(sys.argv[2], 0)

with open(path, 'rb') as f:
    elf = ELFFile(f)
    t = elf.get_section_by_name('.text')
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    ins = list(md.disasm(t.data(), t['sh_addr']))

for i, x in enumerate(ins):
    if x.mnemonic != 'add' or '[' in x.op_str:
        continue
    try:
        d, s, imm = x.op_str.split(', ')
        imm = int(imm.lstrip('#'), 0)
    except ValueError:
        continue
    if not s.startswith('x'):
        continue
    for back in range(1, 10):
        j = i - back
        if j < 0:
            break
        y = ins[j]
        if y.mnemonic == 'adrp' and y.op_str.split(',')[0].strip() == s:
            v = int(y.op_str.split('#')[1], 0) + imm
            if v == target:
                print(f"0x{x.address:x}")
            break
