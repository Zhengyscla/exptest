import sys
from elftools.elf.elffile import ELFFile

path = sys.argv[1]
needles = sys.argv[2:]

with open(path, 'rb') as f:
    elf = ELFFile(f)
    data = open(path, 'rb').read()
    # find strings in any alloc section, report vaddr
    for s in elf.iter_sections():
        if s['sh_type'] != 'SHT_PROGBITS' or not (s['sh_flags'] & 0x2):
            continue
        blob = s.data()
        for n in needles:
            b = n.encode()
            i = 0
            while True:
                i = blob.find(b, i)
                if i < 0:
                    break
                print(f"{n!r} @ vaddr 0x{s['sh_addr']+i:016x} (section {s.name})")
                i += 1
