import sys
from elftools.elf.elffile import ELFFile

ELF = r'work\vmlinux.elf'
BASE = 0xffffffc010000000

names = [
    '_text', '__secure_computing', 'remove_waiter', 'commit_creds', 'prepare_creds',
    'copy_creds', 'cred_init', '__sched_setscheduler', 'sched_move_task', 'release_task',
    'init_task', 'init_cred', 'empty_zero_page', 'root_task_group', 'root_user',
    'init_user_ns', 'init_groups', 'init_nsproxy', 'selinux_state',
    'selinux_blob_sizes', 'security_hook_heads', 'nfulnl_logger', 'loggers',
    'sysctl_bootid', 'selinux_checkreqprot_boot', 'checkreqprot_setup', 'selinux_init',
    'get_selinux_enforcing', 'sel_read_enforce', 'kmem_cache_create',
    'avc_has_perm', 'avc_has_perm_noaudit', 'selinux_inode_permission',
]

with open(ELF, 'rb') as f:
    elf = ELFFile(f)
    sym = elf.get_section_by_name('.symtab')
    got = {}
    for s in sym.iter_symbols():
        n = s.name
        if n in names and n not in got:
            got[n] = s['st_value']

print(f"{'symbol':28s} {'VA':18s} {'offset from _text':18s} {'decimal'}")
for n in names:
    v = got.get(n)
    if v is None:
        print(f"{n:28s} {'MISSING':18s}")
        continue
    off = v - BASE
    print(f"{n:28s} 0x{v:016x} 0x{off:012x}     {off}")
