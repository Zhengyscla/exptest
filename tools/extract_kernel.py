"""Extract the (gzip-compressed) kernel from an Android boot image v2.

Usage:  python extract_kernel.py <boot.img> <out-Image>
Only boot header v2 (page_size 2048/4096, kernel at page_size offset) is handled,
which is what BOOT.img of this device uses.
"""
import gzip
import struct
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, 'rb') as f:
        data = f.read()
    if data[:8] != b'ANDROID!':
        print('not an Android boot image')
        return 1
    kernel_size = struct.unpack_from('<I', data, 8)[0]
    page_size = struct.unpack_from('<I', data, 36)[0]
    header_version = struct.unpack_from('<I', data, 40)[0]
    print(f'kernel_size={kernel_size} page_size={page_size} header_version={header_version}')
    payload = data[page_size:page_size + kernel_size]
    if payload[:2] != b'\x1f\x8b':
        print('kernel payload is not gzip (only gzip is handled here)')
        return 1
    image = gzip.decompress(payload)
    with open(dst, 'wb') as f:
        f.write(image)
    print(f'wrote {dst}: {len(image)} bytes, text_offset=0x{struct.unpack_from("<Q", image, 8)[0]:x}, '
          f'image_size=0x{struct.unpack_from("<Q", image, 16)[0]:x}, magic={image[0x38:0x3c]!r}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
