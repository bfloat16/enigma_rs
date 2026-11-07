"""Compare x64 VM startup with rebuilt native startup without running host code.

Usage: python test/compare_x64_startup.py runtime.dll unpacked.exe
Requires pefile, capstone and unicorn. runtime.dll is RVA-mapped output from
`enigma-rs INPUT --mode runtime -o runtime.dll`.
"""
import argparse
import random
import struct
from pathlib import Path

import capstone
import pefile
import unicorn as u
from unicorn import x86_const as x

REGS = [getattr(x, 'UC_X86_REG_' + r) for r in
        ('RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI',
         'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15')]
LOADER, DISPATCH, HEAP = 0x180000000, 0x190000000, 0x191000000
CONTEXT, STACK, CALLBACKS = 0x1A0000000, 0x200000000, 0x1B0000000


def profile(b):
    pe = pefile.PE(data=b)
    dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    dis.detail = True
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    header = next(i.operands[1].imm for i in dis.disasm(b[ep:ep+48], ep)
                  if i.mnemonic in ('mov', 'movabs') and i.op_str.startswith('r8,'))
    at = struct.unpack_from('<I', b, header + 8)[0]
    end = at + 4 + struct.unpack_from('<I', b, at)[0]
    count, _ = struct.unpack_from('<II', b, at + 4)
    at += 12
    streams = []
    for _ in range(count):
        rva, size = struct.unpack_from('<II', b, at)
        at += 8
        streams.append((rva, at, size))
        at += size
    count = struct.unpack_from('<I', b, at)[0]
    at += 4
    handlers = {}
    for _ in range(count):
        selector, size = struct.unpack_from('<II', b, at)
        at += 8
        handlers[selector] = b[at:at+size]
        at += size
    patches = struct.unpack_from('<12I', b, at)
    return streams, handlers, patches, b[at+48:end]


def execute(runtime, rebuilt, seed, virtual):
    streams, handlers, patches, dispatcher = profile(runtime)
    pe = pefile.PE(data=rebuilt)
    base = pe.OPTIONAL_HEADER.ImageBase
    image = pe.get_memory_mapped_image()
    root = next(rva for rva, _, _ in streams if rva < pe.OPTIONAL_HEADER.SizeOfImage)
    uc = u.Uc(u.UC_ARCH_X86, u.UC_MODE_64)
    for address, size in [(base, len(image)), (LOADER, len(runtime)),
                          (DISPATCH, 0x10000), (HEAP, 0x800000),
                          (CONTEXT, 0x10000), (STACK, 0x200000), (CALLBACKS, 0x10000)]:
        uc.mem_map(address, (size + 4095) & ~4095)
    uc.mem_write(base, bytes(image))
    uc.mem_write(LOADER, runtime)
    dispatcher = bytearray(dispatcher)
    for index, at in enumerate(patches[:9]):
        value = DISPATCH if index == 3 else DISPATCH + patches[10] if index == 6 else CALLBACKS + index * 16
        struct.pack_into('<Q', dispatcher, at, value)
    uc.mem_write(DISPATCH, bytes(dispatcher))
    rng = random.Random(seed)
    for reg in REGS:
        uc.reg_write(reg, rng.getrandbits(64))
    # Exercise both qword stack alignments and different arithmetic flag inputs.
    sp = STACK + 0x100000 + (seed % 16) * 8
    uc.reg_write(x.UC_X86_REG_RSP, sp)
    uc.reg_write(x.UC_X86_REG_EFLAGS, 2 | rng.getrandbits(12) & 0x8D5)
    uc.mem_write(sp, bytes(rng.getrandbits(8) for _ in range(256)))
    cursor = HEAP
    compiled, thunks, events = {}, {}, []

    def qword(address):
        return struct.unpack('<Q', uc.mem_read(address, 8))[0]

    def allocate(code):
        nonlocal cursor
        at = cursor
        uc.mem_write(at, code)
        cursor = (at + len(code) + 15) & ~15
        assert cursor < HEAP + 0x800000
        return at

    def callback(index):
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        args = [qword(stack + 0x28 + n * 8) for n in range(3)]
        if index == 2:
            result = base
        elif index == 1:
            result = CONTEXT
        elif index == 4:
            result = next((LOADER + at for rva, at, size in streams if base + rva == args[0]), 0)
        elif index == 5:
            result = max((LOADER + at for rva, at, size in streams if LOADER + at < args[0]), default=0)
        elif index == 0:
            source = args[0]
            if source not in thunks:
                code = bytes.fromhex('6a00ff3506000000ff2508000000')
                thunks[source] = allocate(code + struct.pack('<QQ', source, DISPATCH + patches[9]))
            result = thunks[source]
        elif index == 7:
            selector, tail = args[:2]
            assert tail == DISPATCH + patches[10]
            if selector not in compiled:
                code = handlers[selector]
                compiled[selector] = allocate(code + b'\xe9' + struct.pack('<i', tail - cursor - len(code) - 5))
            result = compiled[selector]
        elif index == 8:
            source, destination, size = args
            assert size < 0x10000
            for n in range(size):
                uc.mem_write(destination + n, bytes(uc.mem_read(source + n, 1)))
            result = destination
        else:
            raise AssertionError(f'Unknown callback {index}')
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, qword(stack))
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)

    entered = False

    def hook(uc, pc, size, data):
        nonlocal entered
        if virtual and pc == base + root and not entered:
            entered = True
            stack = uc.reg_read(x.UC_X86_REG_RSP) - 8
            uc.mem_write(stack, struct.pack('<Q', pc + 5))
            uc.reg_write(x.UC_X86_REG_RSP, stack)
            uc.reg_write(x.UC_X86_REG_RIP, DISPATCH)
        elif virtual and CALLBACKS <= pc < CALLBACKS + 144:
            callback((pc - CALLBACKS) // 16)
        elif base <= pc < base + len(image) and not base + root - 32 <= pc < base + root + 32:
            stack = uc.reg_read(x.UC_X86_REG_RSP)
            events.append((pc - base, [uc.reg_read(r) for r in REGS],
                           uc.reg_read(x.UC_X86_REG_EFLAGS) & 0x8D5,
                           bytes(uc.mem_read(sp, 128))))
            if len(events) == 1:
                # Model an arbitrary Windows ABI callee; never execute host code.
                for reg in (x.UC_X86_REG_RAX, x.UC_X86_REG_RCX, x.UC_X86_REG_RDX,
                            x.UC_X86_REG_R8, x.UC_X86_REG_R9, x.UC_X86_REG_R10, x.UC_X86_REG_R11):
                    uc.reg_write(reg, rng.getrandbits(64))
                uc.reg_write(x.UC_X86_REG_EFLAGS, 2 | rng.getrandbits(12) & 0x8D5)
                uc.reg_write(x.UC_X86_REG_RIP, qword(stack))
                uc.reg_write(x.UC_X86_REG_RSP, stack + 8)
            else:
                uc.emu_stop()
    uc.hook_add(u.UC_HOOK_CODE, hook)
    uc.emu_start(base + pe.OPTIONAL_HEADER.AddressOfEntryPoint, 0, count=2_000_000)
    assert len(events) == 2
    return events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runtime', type=Path)
    parser.add_argument('rebuilt', type=Path)
    args = parser.parse_args()
    runtime, rebuilt = args.runtime.read_bytes(), args.rebuilt.read_bytes()
    for seed in range(16):
        assert execute(runtime, rebuilt, seed, True) == execute(runtime, rebuilt, seed, False), seed
    print('16 VM/native comparisons passed: transfers, all GPRs, arithmetic flags, caller stack')


if __name__ == '__main__':
    main()
