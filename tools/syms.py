import sys
from elftools.elf.elffile import ELFFile

path = sys.argv[1]
want = sys.argv[2:]

with open(path, 'rb') as f:
    elf = ELFFile(f)
    symtab = elf.get_section_by_name('.symtab') or elf.get_section_by_name('.dynsym')
    secs = {s.name: s for s in elf.iter_sections()}
    if symtab is None:
        print('no symtab; sections:', list(secs))
        sys.exit(1)
    got = {}
    for s in symtab.iter_symbols():
        n = s.name
        if n in want and n not in got:
            got[n] = (s['st_value'], s['st_size'], s['st_info']['type'])
    for n in want:
        v = got.get(n)
        print(f"{n:32s} " + (f"0x{v[0]:016x} size=0x{v[1]:x} {v[2]}" if v else "MISSING"))
    print('--- sections ---')
    for name, s in secs.items():
        print(f"{name:24s} addr=0x{s['sh_addr']:016x} off=0x{s['sh_offset']:x} size=0x{s['sh_size']:x}")
