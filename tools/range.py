import sys
from elftools.elf.elffile import ELFFile

path = sys.argv[1]
lo = int(sys.argv[2], 0)
hi = int(sys.argv[3], 0)

rows = []
with open(path, 'rb') as f:
    elf = ELFFile(f)
    symtab = elf.get_section_by_name('.symtab')
    for s in symtab.iter_symbols():
        v = s['st_value']
        if lo <= v < hi:
            rows.append((v, s['st_size'], s.name))
for v, sz, n in sorted(rows):
    print(f"0x{v:016x} +0x{sz:x} {n}")
