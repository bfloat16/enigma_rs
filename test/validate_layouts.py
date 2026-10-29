"""Run static recovery on a sample directory and validate the rebuilt PE files.

Only enigma-rs is launched. Samples and reconstructed executables are not run.
Uses the Python standard library; native startup probes are a separate opt-in.
"""

import argparse
import ctypes
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import time
from ctypes import wintypes as W
from pathlib import Path


def image_mapping(path):
    if sys.platform != "win32":
        return {"tested": False}
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.argtypes = [
        W.LPCWSTR,
        W.DWORD,
        W.DWORD,
        W.LPVOID,
        W.DWORD,
        W.DWORD,
        W.HANDLE,
    ]
    k.CreateFileW.restype = W.HANDLE
    k.CreateFileMappingW.argtypes = [
        W.HANDLE,
        W.LPVOID,
        W.DWORD,
        W.DWORD,
        W.DWORD,
        W.LPCWSTR,
    ]
    k.CreateFileMappingW.restype = W.HANDLE
    k.MapViewOfFile.argtypes = [W.HANDLE, W.DWORD, W.DWORD, W.DWORD, ctypes.c_size_t]
    k.MapViewOfFile.restype = W.LPVOID
    k.UnmapViewOfFile.argtypes = [W.LPCVOID]
    k.CloseHandle.argtypes = [W.HANDLE]
    file = k.CreateFileW(str(path.resolve()), 0x80000000, 7, None, 3, 0, None)
    assert file != ctypes.c_void_p(-1).value, ctypes.get_last_error()
    mapping = view = None
    try:
        mapping = k.CreateFileMappingW(file, None, 0x11000002, 0, 0, None)
        assert mapping, ctypes.get_last_error()
        view = k.MapViewOfFile(mapping, 4, 0, 0, 0)
        assert view, ctypes.get_last_error()
        assert ctypes.string_at(view, 2) == b"MZ"
        return {"tested": True, "passed": True, "mode": "SEC_IMAGE_NO_EXECUTE"}
    finally:
        if view:
            k.UnmapViewOfFile(view)
        if mapping:
            k.CloseHandle(mapping)
        k.CloseHandle(file)


def u16(b, at):
    return struct.unpack_from("<H", b, at)[0]


def u32(b, at):
    return struct.unpack_from("<I", b, at)[0]


def inspect_pe(b):
    assert b[:2] == b"MZ"
    nt = u32(b, 0x3C)
    assert b[nt : nt + 4] == b"PE\0\0" and u16(b, nt + 4) == 0x14C
    opt = nt + 24
    assert u16(b, opt) == 0x10B
    sections = []
    table = opt + u16(b, nt + 20)
    for i in range(u16(b, nt + 6)):
        at = table + i * 40
        vs, rva, rs, raw = struct.unpack_from("<4I", b, at + 8)
        assert raw + rs <= len(b)
        sections.append((rva, vs, raw, rs, u32(b, at + 36)))

    def read(rva, n):
        if rva < u32(b, opt + 60):
            return b[rva : rva + n]
        s = next(s for s in sections if s[0] <= rva < s[0] + max(s[1], s[3]))
        off = rva - s[0]
        assert off + n <= s[3]
        return b[s[2] + off : s[2] + off + n]

    entry = u32(b, opt + 16)
    assert any(rva <= entry < rva + max(vs, rs) and flags & 0x20000000 for rva, vs, raw, rs, flags in sections)
    directory = opt + 96
    at = u32(b, directory + 8)
    imports = 0
    groups = 0
    assert at
    while True:
        d = struct.unpack("<5I", read(at, 20))
        if not any(d):
            break
        assert d[0] and d[3] and d[4]
        p = d[0]
        iat = d[4]
        while True:
            thunk = u32(read(p, 4), 0)
            assert u32(read(iat, 4), 0) == thunk
            if not thunk:
                break
            if not thunk & 0x80000000:
                name = read(thunk + 2, 1)
                assert 32 <= name[0] < 127
            imports += 1
            p += 4
            iat += 4
        groups += 1
        at += 20
        assert groups < 65536
    reloc_count = 0
    rva, size = struct.unpack_from("<2I", b, directory + 40)
    if rva:
        reloc = read(rva, size)
        p = 0
        while p < len(reloc):
            page, n = struct.unpack_from("<2I", reloc, p)
            assert n >= 8 and n % 2 == 0 and p + n <= len(reloc)
            for i in range(p + 8, p + n, 2):
                v = u16(reloc, i)
                assert v >> 12 in [0, 3]
                if v >> 12 == 3:
                    read(page + (v & 0xFFF), 4)
                    reloc_count += 1
            p += n
    field = opt + 64
    total = 0
    for i in range(0, len(b), 2):
        if field <= i < field + 4:
            continue
        total += b[i] + ((b[i + 1] if i + 1 < len(b) else 0) << 8)
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    assert u32(b, field) == total + len(b)
    return {
        "entry": hex(entry),
        "sections": len(sections),
        "imports": imports,
        "import_groups": groups,
        "relocations": reloc_count,
        "checksum": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", type=Path)
    parser.add_argument("samples", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--mod", choices=["cuda", "wgpu", "cpu"])
    parser.add_argument("--reference", type=Path)
    parser.add_argument(
        "--manifest",
        type=Path,
        help="replay source EXEs from a saved validation report",
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    rows = []
    if args.manifest:
        saved = json.loads(args.manifest.read_text(encoding="utf-8"))
        sources = sorted(Path(row["source"]).resolve() for row in saved["samples"])
        assert all(source.is_file() and source.is_relative_to(args.samples.resolve()) for source in sources)
    else:
        sources = sorted(path for path in args.samples.rglob("*.exe") if "unpack" not in path.relative_to(args.samples).parts[:-1])
    for source in sources:
        if ".unpack." in source.name.lower():
            continue
        relative = source.resolve().relative_to(args.samples.resolve())
        # The CLI always writes next to its input. Use a fresh working copy,
        # keeping the source corpus read-only and separate inputs independent.
        folder = args.output / relative.parent / source.stem
        folder.mkdir(parents=True, exist_ok=False)
        copied = folder / source.name
        shutil.copyfile(source, copied)
        output = folder / "unpack" / source.name
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        started = time.perf_counter()
        command = [str(args.exe.resolve()), str(copied)]
        if args.mod:
            command += ["--mod", args.mod]
        p = subprocess.run(
            command,
            check=False,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
        )
        (folder / "validation.log").write_text(p.stderr, encoding="utf-8")
        row = {
            "source": str(source),
            "source_sha256": before,
            "returncode": p.returncode,
            "seconds": time.perf_counter() - started,
            "log": p.stderr,
        }
        assert hashlib.sha256(source.read_bytes()).hexdigest() == before
        assert hashlib.sha256(copied.read_bytes()).hexdigest() == before
        if p.returncode == 0:
            data = output.read_bytes()
            row.update(
                output=str(output),
                output_sha256=hashlib.sha256(data).hexdigest(),
                pe=inspect_pe(data),
                mapping=image_mapping(output),
            )
            if args.reference:
                reference = args.reference / relative.parent / "game.exe"
                if reference.is_file():
                    assert data == reference.read_bytes()
                    row["reference_equal"] = True
        rows.append(row)
        (args.output / "validation.json").write_text(
            json.dumps(
                {
                    "passed": all(r["returncode"] == 0 for r in rows),
                    "samples_executed": False,
                    "samples": rows,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        print(relative.parent, p.returncode, flush=True)
    assert rows and all(r["returncode"] == 0 for r in rows), "sample recovery failed; see validation.json"


if __name__ == "__main__":
    main()
