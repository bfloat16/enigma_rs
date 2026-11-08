"""Compare release binaries on one VM entry, without executing the sample.

python test/benchmark_devirt.py OLD.exe NEW.exe INPUT.exe 0xf1de7 OUTPUT_DIR

Build both binaries before running. Runs are sequential and alternate order;
every generated machine-code file must match the baseline exactly.
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import sys
import time


def peak_memory_reader(pid):
    """Query Windows' recorded peak after exit while holding a process handle."""
    if sys.platform != 'win32':
        return lambda: None
    import ctypes as c
    from ctypes import wintypes as w

    class Counters(c.Structure):
        _fields_ = [('cb', w.DWORD), ('faults', w.DWORD)] + [
            (name, c.c_size_t) for name in ('peak', 'working', 'peak_paged', 'paged',
                                          'peak_nonpaged', 'nonpaged', 'pagefile', 'peak_pagefile')]

    kernel = c.WinDLL('kernel32', use_last_error=True)
    psapi = c.WinDLL('psapi', use_last_error=True)
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    psapi.GetProcessMemoryInfo.argtypes = [w.HANDLE, c.POINTER(Counters), w.DWORD]
    psapi.GetProcessMemoryInfo.restype = w.BOOL
    handle = kernel.OpenProcess(0x410, False, pid)

    def finish():
        if not handle:
            return None
        try:
            counters = Counters()
            counters.cb = c.sizeof(counters)
            if psapi.GetProcessMemoryInfo(handle, c.byref(counters), counters.cb):
                return counters.peak
            return None
        finally:
            kernel.CloseHandle(handle)
    return finish


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('input', type=Path)
    parser.add_argument('rva')
    parser.add_argument('output', type=Path)
    parser.add_argument('--runs', type=int, default=3)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error('--runs must be positive')
    args.output.mkdir(parents=True, exist_ok=False)
    expected = None
    rows = []
    for run in range(args.runs):
        order = [('baseline', args.baseline), ('candidate', args.candidate)]
        if run % 2:
            order.reverse()
        for label, binary in order:
            name = f'{run + 1}-{label}'
            output = args.output / (name + '.bin')
            command = [str(binary.resolve()), str(args.input.resolve()), '--mode',
                       'devirt', args.rva, '-o', str(output.resolve())]
            started = time.perf_counter()
            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
                read_peak = peak_memory_reader(process.pid)
                try:
                    _, stderr = process.communicate()
                    seconds = time.perf_counter() - started
                finally:
                    peak = read_peak()
            (args.output / (name + '.log')).write_bytes(stderr)
            if process.returncode:
                raise RuntimeError(f'{name} failed; see {name}.log')
            emitted = output.read_bytes()
            if expected is None:
                expected = emitted
            if emitted != expected:
                raise AssertionError(f'{name}: emitted code differs from baseline')
            rows.append(dict(build=label, run=run + 1, seconds=seconds,
                             peak_working_set_bytes=peak,
                             bytes=len(emitted), sha256=hashlib.sha256(emitted).hexdigest()))
            memory = f', peak {peak / 1024**2:.1f} MiB' if peak is not None else ''
            print(f'{name}: {seconds:.3f}s{memory}, {len(emitted)} bytes, exact match', flush=True)
    medians = {label: statistics.median(r['seconds'] for r in rows if r['build'] == label)
               for label in ('baseline', 'candidate')}
    report = dict(input=str(args.input.resolve()),
                  input_sha256=hashlib.sha256(args.input.read_bytes()).hexdigest(),
                  binary_sha256={label: hashlib.sha256(binary.read_bytes()).hexdigest()
                                 for label, binary in [('baseline', args.baseline), ('candidate', args.candidate)]},
                  rva=args.rva, runs=rows, median_seconds=medians,
                  speedup=medians['baseline'] / medians['candidate'])
    (args.output / 'benchmark.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f"Median: {medians['baseline']:.3f}s -> {medians['candidate']:.3f}s "
          f"({report['speedup']:.2f}x)")


if __name__ == '__main__':
    main()
