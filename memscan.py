"""Cross-platform read-only process-memory float scanner (two-pass).

Pass 1 (scan): find every aligned 4-byte slot in readable memory holding a
  float value; save candidate addresses to a hits file.
Pass 2 (refilter): re-read saved candidates, keep those now holding a new value.

Usage:
  python memscan.py scan --proc NAME_OR_PID --float VALUE --out hits.bin
  python memscan.py refilter --proc NAME_OR_PID --float NEWVALUE --in hits.bin

Backends: Windows via ctypes (OpenProcess/ReadProcessMemory/VirtualQueryEx),
  Linux via /proc/PID/maps + /proc/PID/mem. Read-only: never writes memory.
  macOS is NOT supported for memory reads (no /proc); the script exits
  cleanly with an explanation there.
Platform notes: process lookup uses tasklist on Windows, pgrep on Linux/macOS.
"""
import argparse
import os
import struct
import subprocess
import sys
from pathlib import Path

MAX_HITS = 400000
U64 = struct.Struct("<Q")


def default_hits_path():
    return str(Path.home() / "float_hits.bin")


def resolve_pid(proc):
    """Accept a PID or process name; return int PID or None."""
    s = str(proc).strip()
    if s.isdigit():
        pid = int(s)
        if _pid_exists(pid):
            return pid
        return None
    if os.name == "nt":
        return _pidof_windows(s)
    return _pidof_linux(s)


def _pid_exists(pid):
    """Check a PID exists without touching the process.

    NOTE: os.kill(pid, 0) must NOT be used on Windows: signal 0 equals
    CTRL_C_EVENT there, so it can deliver Ctrl+C to the target's console
    instead of merely probing. Use OpenProcess on Windows instead.
    """
    if os.name == "nt":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            k32.OpenProcess.restype = ctypes.c_void_p
            k32.CloseHandle.argtypes = [ctypes.c_void_p]
            h = k32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
            if not h:
                return False
            k32.CloseHandle(h)
            return True
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _pidof_windows(name):
    # Try tasklist CSV first, fall back to PowerShell Get-Process.
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq " + name, "/FO", "CSV"],
            text=True, stderr=subprocess.DEVNULL, timeout=15)
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 2 and parts[1].strip('"').isdigit():
                return int(parts[1].strip('"'))
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-Process -Name '%s' -ErrorAction SilentlyContinue | "
             "Select-Object -ExpandProperty Id" % name.replace("'", "''").replace(".exe", "")],
            text=True, stderr=subprocess.DEVNULL, timeout=15)
        for line in out.splitlines():
            line = line.strip()
            if line.isdigit():
                return int(line)
    except Exception:
        pass
    return None


def _pidof_linux(name):
    for args in (["pgrep", "-x", name], ["pgrep", "-f", name]):
        try:
            out = subprocess.check_output(args, text=True,
                                          stderr=subprocess.DEVNULL, timeout=15)
            for line in out.splitlines():
                line = line.strip()
                if line.isdigit():
                    return int(line)
        except Exception:
            continue
    return None


# ---------------- Windows backend (ctypes) ----------------

def _win_handle():
    """Return (ctypes, kernel32) with 64-bit-safe prototypes set."""
    import ctypes
    k32 = ctypes.windll.kernel32
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
    k32.CloseHandle.restype = ctypes.c_bool
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.c_size_t]
    k32.ReadProcessMemory.restype = ctypes.c_bool
    k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.c_size_t,
                                      ctypes.POINTER(ctypes.c_size_t)]
    return ctypes, k32


def win_scan(pid, target: bytes):
    """Scan committed private readable regions via VirtualQueryEx + RPM."""
    import ctypes
    _, k32 = _win_handle()
    PROCESS_QUERY = 0x0400
    PROCESS_VM_READ = 0x0010
    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000
    PAGE_GUARD = 0x100
    # Readable data/code protections (low byte of Protect); NOACCESS excluded,
    # guard pages excluded separately. NOTE: this deliberately differs from an
    # early draft that masked with 0xF0 (which wrongly dropped plain
    # PAGE_READWRITE heap where game values actually live).
    READABLE = (0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)
    MAX_ADDR = 0x7FFFFFFFFFFF

    class MI(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", ctypes.c_uint32),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", ctypes.c_uint32),
                    ("Protect", ctypes.c_uint32),
                    ("Type", ctypes.c_uint32)]

    h = k32.OpenProcess(PROCESS_QUERY | PROCESS_VM_READ, False, pid)
    if not h:
        raise OSError("OpenProcess failed for pid %d" % pid)
    try:
        mi, addr, hits = MI(), 0, []
        while True:
            if k32.VirtualQueryEx(h, ctypes.c_void_p(addr),
                                  ctypes.byref(mi), ctypes.sizeof(mi)) == 0:
                break
            base = mi.BaseAddress or 0
            # Committed private heap/data pages that are readable and not guarded.
            if (mi.State == MEM_COMMIT and mi.Type == MEM_PRIVATE
                    and (mi.Protect & 0xFF) in READABLE
                    and not (mi.Protect & PAGE_GUARD)
                    and 0 < mi.RegionSize < 0x40000000):
                buf = ctypes.create_string_buffer(mi.RegionSize)
                got = ctypes.c_size_t(0)
                ok = k32.ReadProcessMemory(h, ctypes.c_void_p(base), buf,
                                           mi.RegionSize, ctypes.byref(got))
                if ok and got.value == mi.RegionSize:
                    data = buf.raw
                    off = 0
                    while True:
                        off = data.find(target, off)
                        if off < 0:
                            break
                        if off % 4 == 0:
                            hits.append(base + off)
                            if len(hits) >= MAX_HITS:
                                return hits
                        off += 1
            nxt = base + mi.RegionSize
            if nxt <= addr or nxt >= MAX_ADDR:
                break
            addr = nxt
        return hits
    finally:
        k32.CloseHandle(h)


def win_read_floats(pid, addrs, target: bytes):
    """Re-read 4 bytes at each addr; return survivors matching target."""
    import ctypes
    _, k32 = _win_handle()
    h = k32.OpenProcess(0x0400 | 0x0010, False, pid)
    if not h:
        raise OSError("OpenProcess failed for pid %d" % pid)
    try:
        surv = []
        for a in addrs:
            buf = ctypes.create_string_buffer(4)
            got = ctypes.c_size_t(0)
            ok = k32.ReadProcessMemory(h, ctypes.c_void_p(a), buf, 4, ctypes.byref(got))
            if ok and got.value == 4 and buf.raw == target:
                surv.append(a)
        return surv
    finally:
        k32.CloseHandle(h)


# ---------------- Linux backend (/proc) ----------------

def linux_regions(pid):
    """Parse /proc/PID/maps; return [(start, size)] of readable regions."""
    regions = []
    try:
        with open("/proc/%d/maps" % pid, "r") as f:
            for line in f:
                try:
                    rng, perms = line.split()[:2]
                    if "r" not in perms:
                        continue
                    s, e = rng.split("-")
                    start, end = int(s, 16), int(e, 16)
                    size = end - start
                    if 0 < size < 0x40000000:
                        regions.append((start, size))
                except (ValueError, IndexError):
                    continue
    except OSError as e:
        raise OSError("cannot read /proc/%d/maps: %s" % (pid, e))
    return regions


def linux_scan(pid, target: bytes):
    regions = linux_regions(pid)
    hits = []
    try:
        fd = os.open("/proc/%d/mem" % pid, os.O_RDONLY)
    except OSError as e:
        raise OSError("cannot open /proc/%d/mem (need ptrace rights / same user): %s" % (pid, e))
    try:
        for base, size in regions:
            try:
                data = os.pread(fd, size, base)
            except OSError:
                continue  # unmapped / vsyscall gaps; skip
            if len(data) != size:
                continue
            off = 0
            while True:
                off = data.find(target, off)
                if off < 0:
                    break
                if off % 4 == 0:
                    hits.append(base + off)
                    if len(hits) >= MAX_HITS:
                        return hits
                off += 1
    finally:
        os.close(fd)
    return hits


def linux_read_floats(pid, addrs, target: bytes):
    surv = []
    try:
        fd = os.open("/proc/%d/mem" % pid, os.O_RDONLY)
    except OSError as e:
        raise OSError("cannot open /proc/%d/mem: %s" % (pid, e))
    try:
        for a in addrs:
            try:
                data = os.pread(fd, 4, a)
            except OSError:
                continue
            if data == target:
                surv.append(a)
    finally:
        os.close(fd)
    return surv


# ---------------- hits file + CLI ----------------

def save_hits(path: Path, hits):
    with open(path, "wb") as f:
        f.write(U64.pack(len(hits)))
        for a in hits:
            f.write(U64.pack(a))


def load_hits(path: Path):
    blob = Path(path).read_bytes()
    if len(blob) < 8:
        raise ValueError("hits file too small: %s" % path)
    (n,) = U64.unpack_from(blob, 0)
    if 8 + n * 8 != len(blob):
        raise ValueError("hits file corrupt: header says %d but size is %d" % (n, len(blob)))
    return [U64.unpack_from(blob, 8 + i * 8)[0] for i in range(n)]


def do_scan(args):
    pid = resolve_pid(args.proc)
    if pid is None:
        print("error: process not found: %s" % args.proc, file=sys.stderr)
        return 1
    try:
        target = struct.pack("<f", args.float)
    except (struct.error, OverflowError) as e:
        print("error: bad float value: %s" % e, file=sys.stderr)
        return 1
    if sys.platform == "darwin":
        print("error: memory scanning is not supported on macOS (no /proc); "
              "Windows and Linux only", file=sys.stderr)
        return 1
    try:
        if os.name == "nt":
            hits = win_scan(pid, target)
        else:
            hits = linux_scan(pid, target)
    except OSError as e:
        print("error: scan failed: %s" % e, file=sys.stderr)
        return 1
    try:
        save_hits(Path(args.out), hits)
    except OSError as e:
        print("error: cannot write %s: %s" % (args.out, e), file=sys.stderr)
        return 1
    print("scan candidates: %d (pid %d) -> %s" % (len(hits), pid, args.out))
    if len(hits) >= MAX_HITS:
        print("note: hit cap %d reached; narrow the value or region" % MAX_HITS)
    return 0


def do_refilter(args):
    pid = resolve_pid(args.proc)
    if pid is None:
        print("error: process not found: %s" % args.proc, file=sys.stderr)
        return 1
    try:
        addrs = load_hits(args.hits_in)
    except (OSError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    try:
        target = struct.pack("<f", args.float)
    except (struct.error, OverflowError) as e:
        print("error: bad float value: %s" % e, file=sys.stderr)
        return 1
    if sys.platform == "darwin":
        print("error: memory scanning is not supported on macOS (no /proc); "
              "Windows and Linux only", file=sys.stderr)
        return 1
    try:
        if os.name == "nt":
            surv = win_read_floats(pid, addrs, target)
        else:
            surv = linux_read_floats(pid, addrs, target)
    except OSError as e:
        print("error: refilter failed: %s" % e, file=sys.stderr)
        return 1
    print("survivors: %d / %d" % (len(surv), len(addrs)))
    for a in surv[:40]:
        print(hex(a))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read-only process-memory float scanner.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan memory for a float, save candidates")
    s.add_argument("--proc", required=True, help="process name or PID")
    s.add_argument("--float", required=True, type=float, help="float value to scan for")
    s.add_argument("--out", default=default_hits_path(), help="hits output file")
    s.set_defaults(func=do_scan)
    r = sub.add_parser("refilter", help="narrow saved candidates to a new value")
    r.add_argument("--proc", required=True, help="process name or PID")
    r.add_argument("--float", required=True, type=float, help="current float value")
    r.add_argument("--in", dest="hits_in", required=True, help="hits file from scan")
    r.set_defaults(func=do_refilter)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
