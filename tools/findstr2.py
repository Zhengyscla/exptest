import sys
from elftools.elf.elffile import ELFFile

path = sys.argv[1]
needles = sys.argv[2:]

with open(path, 'rb') as f:
    elf = ELFFile(f)
    for s in elf.iter_sections():
        if s['sh_type'] != 'SHT_PROGBITS' or not (s['sh_flags'] & 0x2):
            continue
        blob = s.data()
        start = 0
        for n in needles:
            b = n.encode()
            i = 0
            while True:
                i = blob.find(b, i)
                if i < 0:
                    break
                a = i
                while a > 0 and blob[a-1] != 0:
                    a -= 1
                z = i
                while z < len(blob) and blob[z] != 0:
                    z += 1
                text = blob[a:z].decode('latin-1')
                print(f"{n!r}: str_start=0x{s['sh_addr']+a:016x} full={text!r}")
                i += 1
                break
