"""Compare emitted x64 functions with their template VM in Unicorn.

Usage: python test/compare_x64_devirt.py runtime.dll protected.exe rebuilt.exe listings
Only emulated VM/native instructions run. Compare up to four external transfers,
modeling callees that return into VM continuations; host code is never invoked. Requires pefile, capstone, unicorn.
"""
import argparse
import json
import random
import re
import struct
from pathlib import Path

import pefile
import unicorn as u
from unicorn import x86_const as x
from compare_x64_startup import profile, REGS

LOADER, DISPATCH, HEAP = 0x180000000, 0x190000000, 0x191000000
CONTEXT, STACK, CALLBACKS = 0x1A0000000, 0x200000000, 0x1B0000000
DATA = 0x300000000


def listing(path):
    text = path.read_text(encoding='utf-8')
    source = int(re.search(r'vm_enter RVA: (0x\w+)', text)[1], 16)
    origin = int(re.search(r'ORG (0x\w+)', text)[1], 16)
    code = bytearray()
    labels = {}
    pending = None
    for line in text.splitlines():
        if line.endswith(':') and not line.startswith(';'):
            pending = line[:-1]
        match = re.search(r'; ([0-9a-f]+)  ([0-9a-f]+)$', line)
        if match:
            address = int(match[1], 16)
            assert address == origin + len(code)
            if pending:
                labels[address] = pending
                pending = None
            code.extend(bytes.fromhex(match[2]))
    return source, origin, bytes(code), labels


def execute(runtime, host_image, base, runtime_rva, function, seed, virtual):
    source, origin, code, labels = function
    streams, handlers, patches, dispatcher = profile(runtime)
    uc = u.Uc(u.UC_ARCH_X86, u.UC_MODE_64)
    for address, size in [(base, max(len(host_image), origin - base + len(code))),
                          (LOADER, len(runtime)), (DISPATCH, 0x10000),
                          (HEAP, 0x1000000), (CONTEXT, 0x10000),
                          (STACK, 0x400000), (CALLBACKS, 0x10000), (DATA, 0x100000)]:
        uc.mem_map(address, (size + 4095) & ~4095)
    uc.mem_write(base, bytes(host_image))
    uc.mem_write(origin, code)
    uc.mem_write(LOADER, runtime)
    dispatcher = bytearray(dispatcher)
    for index, at in enumerate(patches[:9]):
        target = DISPATCH if index == 3 else DISPATCH + patches[10] if index == 6 else CALLBACKS + index * 16
        struct.pack_into('<Q', dispatcher, at, target)
    uc.mem_write(DISPATCH, bytes(dispatcher))
    rng = random.Random(seed)
    sp = STACK + 0x200000 + seed % 16 * 8
    for n, reg in enumerate(REGS):
        uc.reg_write(reg, DATA + (seed % 4) * 8 if n in [1, 3, 5, 6, 7, 12, 13, 14, 15] else seed % 4)
    uc.reg_write(x.UC_X86_REG_RSP, sp)
    uc.reg_write(x.UC_X86_REG_RBP, sp + 0x80)
    uc.reg_write(x.UC_X86_REG_EFLAGS, 2 | rng.getrandbits(12) & 0x8D5)
    uc.mem_write(sp, struct.pack('<Q', base + 0x500) + bytes(248))
    cursor = HEAP
    compiled, thunks, writes = {}, {}, set()
    events = []

    def qword(address):
        return struct.unpack('<Q', uc.mem_read(address, 8))[0]

    def allocate(data):
        nonlocal cursor
        at = cursor
        uc.mem_write(at, data)
        cursor = (at + len(data) + 15) & ~15
        assert cursor < HEAP + 0x1000000
        return at

    def callback(index):
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        arg = lambda n: qword(stack + 0x28 + n * 8)
        if index == 0:
            at = arg(0)
            if at not in thunks:
                thunks[at] = allocate(bytes.fromhex('6a00ff3506000000ff2508000000') + struct.pack('<QQ', at, DISPATCH + patches[9]))
            result = thunks[at]
        elif index == 1:
            result = CONTEXT
        elif index == 2:
            result = base
        elif index == 4:
            result = next((LOADER + at for rva, at, _ in streams if base + rva == arg(0)), 0)
        elif index == 5:
            result = max((LOADER + at for _, at, _ in streams if LOADER + at < arg(0)), default=0)
        elif index == 7:
            selector, tail = arg(0), arg(1)
            assert tail == DISPATCH + patches[10]
            if selector not in compiled:
                data = handlers[selector]
                compiled[selector] = allocate(data + b'\xe9' + struct.pack('<i', tail - cursor - len(data) - 5))
            result = compiled[selector]
        elif index == 8:
            src, dst, size = arg(0), arg(1), arg(2)
            assert size <= 0x10000
            for n in range(size):
                uc.mem_write(dst + n, bytes(uc.mem_read(src + n, 1)))
            result = dst
        else:
            raise AssertionError(f'Unknown callback {index}')
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, qword(stack))
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)

    def normalized(value):
        for at, pointer in thunks.items():
            if pointer == value:
                return f'continuation_{at - LOADER:08x}'
        for _, at, size in streams:
            if LOADER + at <= value < LOADER + at + size:
                return base + runtime_rva + value - LOADER
        return labels.get(value, value)

    def hook(uc, pc, size, data):
        if virtual and CALLBACKS <= pc < CALLBACKS + 144:
            callback((pc - CALLBACKS) // 16)
        elif not (virtual and (DISPATCH <= pc < DISPATCH + len(dispatcher) or HEAP <= pc < cursor)) and not (not virtual and origin <= pc < origin + len(code)):
            current_sp = uc.reg_read(x.UC_X86_REG_RSP)
            assert sp - 0x10000 <= current_sp <= sp + 0x10000, f'guest stack outside fixture: {current_sp:x}'
            stack = [normalized(qword(at)) for at in range(max(sp, current_sp), sp + 248, 8)]
            events.append((normalized(pc), [normalized(uc.reg_read(r)) for r in REGS],
                           uc.reg_read(x.UC_X86_REG_EFLAGS) & 0x8D5, stack))
            return_to = qword(current_sp)
            continuation = normalized(return_to)
            if len(events) < 4 and isinstance(continuation, str) and continuation.startswith('continuation_'):
                # Independent Windows x64 ABI callee model; saved nonvolatile state
                # and caller memory remain observable across native continuations.
                for n in [0, 1, 2, 8, 9, 10, 11]:
                    uc.reg_write(REGS[n], DATA + 0x30000 + rng.randrange(16) * 8)
                uc.reg_write(x.UC_X86_REG_EFLAGS, 2 | rng.getrandbits(12) & 0x8D5)
                uc.reg_write(x.UC_X86_REG_RIP, return_to)
                uc.reg_write(x.UC_X86_REG_RSP, current_sp + 8)
            else:
                uc.emu_stop()

    def memory_write(uc, access, address, size, value, data):
        if not any(lo <= address < hi for lo, hi in [(STACK, sp), (LOADER, LOADER + len(runtime)),
                (DISPATCH, DISPATCH + 0x10000), (HEAP, HEAP + 0x1000000), (CONTEXT, CONTEXT + 0x10000)]):
            writes.update(range(address, address + size))

    def fetch_boundary(uc, access, address, size, value, data):
        hook(uc, address, size, data)
        return False

    mapped_pages = set()
    def missing_data(uc, access, address, size, value, data):
        for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            if page not in mapped_pages:
                assert len(mapped_pages) < 1024, 'guest input expands memory beyond fixture bound'
                uc.mem_map(page, 4096)
                mapped_pages.add(page)
        return True

    uc.hook_add(u.UC_HOOK_MEM_READ_UNMAPPED | u.UC_HOOK_MEM_WRITE_UNMAPPED, missing_data)
    uc.hook_add(u.UC_HOOK_MEM_FETCH_UNMAPPED, fetch_boundary)
    uc.hook_add(u.UC_HOOK_CODE, hook)
    uc.hook_add(u.UC_HOOK_MEM_WRITE, memory_write)
    if virtual:
        uc.mem_write(sp - 8, struct.pack('<Q', base + source + 5))
        uc.reg_write(x.UC_X86_REG_RSP, sp - 8)
    try:
        uc.emu_start(DISPATCH if virtual else origin, 0, count=5_000_000)
    except u.UcError as error:
        if not events:
            raise RuntimeError(f'{source:x} virtual={virtual} pc={uc.reg_read(x.UC_X86_REG_RIP):x} sp={uc.reg_read(x.UC_X86_REG_RSP):x}') from error
    if not events and uc.reg_read(x.UC_X86_REG_RIP) == 0:
        hook(uc, 0, 0, None)
    assert events, 'VM/native did not reach an external transfer'
    final_sp = uc.reg_read(x.UC_X86_REG_RSP)
    return events, [(at, bytes(uc.mem_read(at, 1))) for at in sorted(writes)
                    if not STACK <= at < max(sp, final_sp)]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['runtime', 'protected', 'rebuilt', 'listings']:
        p.add_argument(name, type=Path)
    p.add_argument('--seeds', type=int, default=8)
    args = p.parse_args()
    runtime = args.runtime.read_bytes()
    protected = pefile.PE(str(args.protected))
    rebuilt = pefile.PE(str(args.rebuilt))
    base = protected.OPTIONAL_HEADER.ImageBase
    image = bytearray(protected.OPTIONAL_HEADER.SizeOfImage)
    recovered = rebuilt.get_memory_mapped_image()
    image[:len(recovered)] = recovered
    size = pefile.PE(data=runtime).OPTIONAL_HEADER.SizeOfImage
    engine = [s.VirtualAddress for s in protected.sections if s.Misc_VirtualSize == size]
    assert len(engine) == 1
    image[engine[0]:engine[0] + len(runtime)] = runtime
    rows = []
    for path in sorted(args.listings.glob('*.asm')):
        function = listing(path)
        row = {'rva': hex(function[0]), 'seeds': args.seeds, 'passed': True}
        before = None
        try:
            for seed in range(args.seeds):
                before = execute(runtime, image, base, engine[0], function, seed, True)
                after = execute(runtime, image, base, engine[0], function, seed, False)
                if before != after:
                    raise AssertionError((seed, before, after))
        except Exception as error:
            row.update(passed=False, error=repr(error), expected_target=before[0][0][0] if before else None)
        rows.append(row)
        print(path.name, row['passed'], row.get('expected_target', ''), flush=True)
        (args.listings / 'unicorn.json').write_text(json.dumps(rows, indent=2), encoding='utf-8')
    assert rows and all(row['passed'] for row in rows), 'VM/native mismatch; see unicorn.json'


if __name__ == '__main__':
    main()
