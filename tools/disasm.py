import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

IMG = r'work\Image'
BASE = 0xffffffc010000000

data = open(IMG, 'rb').read()

def disasm(va, length):
    off = va - BASE
    code = data[off:off+length]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return list(md.disasm(code, va))

if __name__ == '__main__':
    va = int(sys.argv[1], 0)
    ln = int(sys.argv[2], 0)
    pat = sys.argv[3] if len(sys.argv) > 3 else None
    for ins in disasm(va, ln):
        txt = f"0x{ins.address:016x}  {ins.mnemonic:8s} {ins.op_str}"
        if pat is None or pat in txt:
            print(txt)
