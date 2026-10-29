"""Independently compare a version-1 EVB with recovered files, without execution.

The fixed configuration and its ctx offsets come from Loader analysis.
Only the Python standard library is used; no Rust decoding code is imported.
"""

import argparse
import hashlib
import json
import struct
from pathlib import Path


def u32(data, at):
    return struct.unpack_from("<I", data, at)[0]


def u64(data, at):
    return struct.unpack_from("<Q", data, at)[0]


def decrypt(data, initial):
    state = list(initial)
    i = j = 0
    output = bytearray()
    for byte in data:
        i = (i + 1) & 255
        j = (j + state[i]) & 255
        state[i], state[j] = state[j], state[i]
        output.append(byte ^ state[(state[i] + state[j]) & 255])
    return bytes(output)


def name(data, at):
    start = at
    while data[at : at + 2] != b"\0\0":
        assert at + 2 <= len(data)
        at += 2
    return data[start:at].decode("utf-16-le"), at + 2


def compare(source, fixed, output, ctx_start, metadata_at, length_at):
    data = source.read_bytes()
    ctx = bytes(ctx_start) + fixed.read_bytes()
    state = ctx[metadata_at : metadata_at + 256]
    content = ctx[metadata_at + 256 : metadata_at + 512]
    assert len(state) == len(content) == 256
    length = u32(ctx, length_at)
    bias = u32(ctx, length_at + 4)
    nt = u32(data, 0x3C)
    table = nt + 24 + struct.unpack_from("<H", data, nt + 20)[0]
    count = struct.unpack_from("<H", data, nt + 6)[0]
    bases = []
    for index in range(count):
        at = table + 40 * index
        raw_size, raw = struct.unpack_from("<2I", data, at + 16)
        if length < 120 or raw_size < bias + length:
            continue
        base = raw + bias
        header = decrypt(data[base + 56 : base + 120], state)
        if u32(header, 4) == 64 and u32(header, 20) == 1 and u64(header, 24) == 120 and u64(header, 48) == length and u64(header, 32) + 120 == length:
            bases.append(base)
    assert len(bases) == 1, bases
    base = bases[0]
    cursor = base + 120
    pending = [(1, Path())]
    rows = []
    while pending:
        remaining, parent = pending.pop()
        if not remaining:
            continue
        pending.append((remaining - 1, parent))
        size = u32(decrypt(data[cursor : cursor + 4], state), 0)
        cursor += 4
        record = decrypt(data[cursor : cursor + size], state)
        assert len(record) == size
        cursor += size
        label, at = name(record, 12)
        kind = record[at]
        at += 1
        item = parent if kind in (0, 1) or label == "%DEFAULT FOLDER%" else parent / label
        if kind == 2:
            at += 2
            size = u64(record, at)
            at += 8 + 29
            _, at = name(record, at)
            stored = u64(record, at)
            assert at + 8 == len(record) and stored == size
            encrypted = data[cursor : cursor + size]
            assert len(encrypted) == size
            plain = b"".join(decrypt(encrypted[n : n + 8192], content) for n in range(0, size, 8192))
            recovered = (output / item).read_bytes()
            assert recovered == plain, item
            rows.append(
                {
                    "path": str(item),
                    "size": size,
                    "sha256": hashlib.sha256(plain).hexdigest(),
                }
            )
            cursor += stored
        else:
            assert kind in (0, 1, 3)
        children = u32(record, 8)
        if children:
            pending.append((children, item))
    assert cursor == base + length
    return {
        "source": str(source),
        "passed": True,
        "files": rows,
        "file_count": len(rows),
        "bytes": sum(r["size"] for r in rows),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("source", "fixed", "output", "report"):
        parser.add_argument(key, type=Path)
    for key in ("ctx-start", "metadata", "length"):
        parser.add_argument("--" + key, type=lambda s: int(s, 0), required=True)
    args = parser.parse_args()
    result = compare(args.source, args.fixed, args.output, args.ctx_start, args.metadata, args.length)
    args.report.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Compared {result['file_count']} files ({result['bytes']} bytes)")


if __name__ == "__main__":
    main()
