import sys, re
from elftools.elf.elffile import ELFFile

path = sys.argv[1]
pats = sys.argv[2:]
rx = [re.compile(p, re.I) for p in pats]

with open(path, 'rb') as f:
    elf = ELFFile(f)
    symtab = elf.get_section_by_name('.symtab')
    for s in symtab.iter_symbols():
        n = s.name
        if not n:
            continue
        for r in rx:
            if r.search(n):
                print(f"0x{s['st_value']:016x} {n}")
                break
