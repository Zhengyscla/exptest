import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

path = sys.argv[1]
targets = set(int(t, 0) for t in sys.argv[2:])
show_all = '--all' in sys.argv

with open(path, 'rb') as f:
    elf = ELFFile(f)
    relocs = {}
    for sec in elf.iter_sections():
        if sec['sh_type'] in ('SHT_RELA', 'SHT_REL'):
            symtab = elf.get_section(sec['sh_link'])
            for r in sec.iter_relocations():
                if r['r_info_type'] == 1027:  # R_AARCH64_RELATIVE
                    relocs[r['r_offset']] = r['r_addend']
    text = elf.get_section_by_name('.text')
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    insns = list(md.disasm(text.data(), text['sh_addr']))

last_adrp = {}
for idx, ins in enumerate(insns):
    if ins.mnemonic == 'adrp':
        try:
            reg, imm = ins.op_str.split(', #')
            last_adrp[reg.strip()] = int(imm, 0)
        except ValueError:
            pass
    elif ins.mnemonic in ('ldr', 'add', 'str') and '[' in ins.op_str:
        try:
            dst, mem = ins.op_str.split(', [')
            base, off = mem.rstrip(']').split(', ')
            off = int(off.lstrip('#'), 0)
        except ValueError:
            continue
        base = base.strip()
        if base not in last_adrp:
            continue
        slot = last_adrp[base] + off
        val = relocs.get(slot)
        if val is None:
            continue
        if show_all or val in targets:
            print(f"0x{ins.address:016x}  {ins.mnemonic} {ins.op_str}   -> slot 0x{slot:x} val 0x{val:x}")
