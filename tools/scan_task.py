import struct, sys

IMG = r'work\Image'
BASE = 0xffffffc010000000
init_task = 0xffffffc0134947c0
init_cred = 0xffffffc0134a46a0
objects = {
    'init_cred': init_cred,
    'root_user': 0xffffffc0134a3500,
    'init_user_ns': 0xffffffc0134a32e8,
    'init_groups': 0xffffffc0134a4748,
    'init_nsproxy': 0xffffffc0134a4530,
    'root_task_group': 0xffffffc013c86780,
}

data = open(IMG, 'rb').read()
off = init_task - BASE
win = data[off:off+0x2000]

print(f"init_task file off 0x{off:x}")
# find swapper strings
import re
for m in re.finditer(rb'swapper[^\x00]*', win):
    print(f"  string @ +0x{m.start():x}: {m.group()}")
# find pointer matches
for name, addr in objects.items():
    pat = struct.pack('<Q', addr)
    idx = 0
    while True:
        i = win.find(pat, idx)
        if i < 0:
            break
        print(f"  {name:16s} ptr @ +0x{i:x}")
        idx = i + 1
# self-referencing list heads: value == address of the field
for i in range(0, 0x1400, 8):
    v = struct.unpack_from('<Q', win, i)[0]
    if v == init_task + i:
        print(f"  self-ptr (empty list head) @ +0x{i:x}")
