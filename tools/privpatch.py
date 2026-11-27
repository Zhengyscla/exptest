import struct, sys

def parse(path):
    d = open(path, 'rb').read()
    magic, ver, fe, be, mw = struct.unpack_from('<IHHHH', d, 0)
    rel_len = struct.unpack_from('<H', d, 12)[0]
    off = 16
    release = d[off:off+rel_len].decode('latin-1')
    off += rel_len
    nsec = struct.unpack_from('<H', d, off)[0]; off += 2
    fields = []
    for _ in range(nsec):
        nl = d[off]; off += 1
        name = d[off:off+nl].decode(); off += nl
        cnt = struct.unpack_from('<I', d, off)[0]; off += 4
        for _ in range(cnt):
            kl = d[off]; off += 1
            key = d[off:off+kl].decode(); off += kl
            val = struct.unpack_from('<Q', d, off)[0]
            fields.append((name, key, off, val))
            off += 8
    return d, release, fields, off

if __name__ == '__main__':
    path = sys.argv[1]
    d, release, fields, end = parse(path)
    print('release', release, 'bytes', len(d), 'parsed', end)
    for s, k, o, v in fields:
        if k in ('mm_struct_sz', 'collisions', 'prepare_max_attempts'):
            print(f'  {s}.{k} = {v}')
    if len(sys.argv) > 3:
        sec, key, val = sys.argv[2], sys.argv[3], int(sys.argv[4], 0)
        buf = bytearray(d)
        done = False
        for s, k, o, v in fields:
            if k == key and (sec == '*' or s == sec):
                struct.pack_into('<Q', buf, o, val)
                print(f'patched {s}.{k}: {v} -> {val}')
                done = True
        if not done:
            print('key not found:', sec, key)
        else:
            open(path, 'wb').write(buf)

