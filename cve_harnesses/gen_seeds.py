#!/usr/bin/env python3
"""Generate seed corpora for CVE-specific fuzz harnesses."""
import os, struct, zlib, gzip, io

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ============================================================
# CVE-2022-37434 seeds: gzip streams with extra fields
# The harness prepends 1 byte (extra_buf_size selector), then
# feeds the rest as gzip data to inflate with inflateGetHeader.
# ============================================================

def make_gzip_with_extra(payload, extra_data):
    """Build a raw gzip byte stream with an FEXTRA field."""
    buf = io.BytesIO()
    # Gzip magic
    buf.write(b'\x1f\x8b')
    # Method: deflate
    buf.write(b'\x08')
    # Flags: FEXTRA (bit 2)
    buf.write(b'\x04')
    # Mtime, xfl, os
    buf.write(b'\x00\x00\x00\x00\x00\xff')
    # XLEN (2 bytes LE)
    buf.write(struct.pack('<H', len(extra_data)))
    buf.write(extra_data)
    # Compressed payload
    co = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    buf.write(co.compress(payload))
    buf.write(co.flush())
    # CRC32 and ISIZE
    buf.write(struct.pack('<I', zlib.crc32(payload) & 0xFFFFFFFF))
    buf.write(struct.pack('<I', len(payload) & 0xFFFFFFFF))
    return buf.getvalue()

cve37434_dir = os.path.join(PROJECT, 'cve_builds/cve-2022-37434/corpus')
os.makedirs(cve37434_dir, exist_ok=True)

payloads = [b'hello', b'A' * 100, bytes(range(256)) * 4]
extra_sizes = [1, 10, 32, 64, 128, 255, 512, 1024]

idx = 0
for payload in payloads:
    for es in extra_sizes:
        extra = bytes([(i * 37) & 0xff for i in range(es)])
        gz = make_gzip_with_extra(payload, extra)
        # Prepend selector byte: we want extra_buf_size < es to trigger the overflow
        for selector in [0, 1, 5, 63]:
            seed = bytes([selector]) + gz
            fname = os.path.join(cve37434_dir, f'seed_{idx:04d}')
            with open(fname, 'wb') as f:
                f.write(seed)
            idx += 1

# Also add standard gzip seeds without extra
for payload in payloads:
    bio = io.BytesIO()
    with gzip.GzipFile(fileobj=bio, mode='wb') as g:
        g.write(payload)
    gz = bio.getvalue()
    for selector in [0, 1, 32, 63]:
        seed = bytes([selector]) + gz
        fname = os.path.join(cve37434_dir, f'seed_{idx:04d}')
        with open(fname, 'wb') as f:
            f.write(seed)
        idx += 1

print(f"CVE-2022-37434: generated {idx} seeds in {cve37434_dir}")

# ============================================================
# CVE-2018-25032 seeds: inputs that produce distant matches
# with Z_FIXED. The harness uses first 2 bytes as parameters.
# The payload needs repeated patterns at varying distances.
# ============================================================

cve25032_dir = os.path.join(PROJECT, 'cve_builds/cve-2018-25032/corpus')
os.makedirs(cve25032_dir, exist_ok=True)

idx = 0

# Pattern 1: repeated blocks at various distances
for dist in [1, 4, 32, 128, 256, 1024, 2048]:
    for block_size in [3, 8, 32]:
        block = bytes([(i * 71) & 0xff for i in range(block_size)])
        filler = bytes([(i * 13) & 0xff for i in range(dist)])
        # Craft payload: block + filler + block (repeat)
        payload = (block + filler + block) * 10
        for level in [1, 6, 9]:
            for wbits_offset in [0, 3, 6]:
                header = bytes([level, wbits_offset])
                seed = header + payload[:4094]
                fname = os.path.join(cve25032_dir, f'seed_{idx:04d}')
                with open(fname, 'wb') as f:
                    f.write(seed)
                idx += 1

# Pattern 2: sliding window stress - many 3-byte matches at max distance
for trial in range(5):
    chunk = bytes([(i * (trial+1) * 7) & 0xff for i in range(258)])
    payload = chunk + b'\x00' * 2000 + chunk + b'\xff' * 1000 + chunk
    for level in [1, 5, 9]:
        header = bytes([level, 4])
        seed = header + payload[:4094]
        fname = os.path.join(cve25032_dir, f'seed_{idx:04d}')
        with open(fname, 'wb') as f:
            f.write(seed)
        idx += 1

# Pattern 3: highly compressible data
for pat in [b'\x00', b'\xff', b'ab', b'abcabc']:
    payload = pat * 4000
    for level in [1, 6, 9]:
        header = bytes([level, 0])
        seed = header + payload[:4094]
        fname = os.path.join(cve25032_dir, f'seed_{idx:04d}')
        with open(fname, 'wb') as f:
            f.write(seed)
        idx += 1

print(f"CVE-2018-25032: generated {idx} seeds in {cve25032_dir}")
