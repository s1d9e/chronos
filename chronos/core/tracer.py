"""Linux syscall tracer built directly on ptrace(2).

Pure-Python (ctypes) implementation — no strace subprocess, no external
instrumentation daemon. It traces the system call stream of a process tree
(following fork/clone/exec), decodes the arguments that matter for malware
analysis (paths, socket addresses, memory protections, I/O buffers) and emits
backend-agnostic ``SyscallEvent`` objects.

Only observation: nothing here modifies the tracee's memory or control flow.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import os
import signal
import socket as _socket
import time
from typing import Any

from chronos import config as cfg
from chronos.events import SyscallEvent

# --- ptrace requests ---------------------------------------------------------
PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_PEEKUSER = 3
PTRACE_CONT = 7
PTRACE_KILL = 8
PTRACE_GETREGS = 12
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GET_SYSCALL_INFO = 0x420E

_SYS_INFO_ENTRY = 1
_SYS_INFO_EXIT = 2

# --- ptrace options ----------------------------------------------------------
_PTRACE_O_TRACEFORK = 0x1
_PTRACE_O_TRACEVFORK = 0x2
_PTRACE_O_TRACECLONE = 0x8
_PTRACE_O_TRACEEXEC = 0x10
_PTRACE_O_TRACEEXIT = 0x40
_PTRACE_O_EXITKILL = 0x100000

_PTRACE_EVENT_FORK = 1
_PTRACE_EVENT_VFORK = 2
_PTRACE_EVENT_CLONE = 3
_PTRACE_EVENT_EXEC = 4
_PTRACE_EVENT_EXIT = 5

SIGTRAP = 5
SIGSTOP = 19
# Syscall-stops are reported with WSTOPSIG == SIGTRAP | 0x80 (0x85).
SIG_SYSCALL = SIGTRAP | 0x80

_PROT = {0x1: "R", 0x2: "W", 0x4: "X"}
_PROT_NONE = 0x0
_MAP_ANON = 0x20
_MAP_SHARED = 0x1
_MAP_PRIVATE = 0x2
_MAP_FIXED = 0x10
_MAP_GROWSDOWN = 0x100
_MAP_EXEC = 0x2000

_O_WRONLY = 0x1
_O_RDWR = 0x2
_O_CREAT = 0x40
_O_EXCL = 0x80
_O_APPEND = 0x400
_O_TRUNC = 0x200
_O_DIRECTORY = 0x10000

_AF_NAMES = {1: "unix", 2: "inet", 10: "inet6", 17: "packet", 45: "netlink"}
_SOCK_NAMES = {1: "stream", 2: "dgram", 3: "raw", 5: "seqpacket", 10: "dccp"}
_PTRACE_REQ = {
    0: "TRACEME",
    2: "PEEKDATA",
    5: "POKEDATA",
    16: "ATTACH",
    17: "DETACH",
    0x4200: "SETOPTIONS",
    0x4201: "GETEVENTMSG",
    0x4206: "SEIZE",
    0x4207: "INTERRUPT",
}

# --- syscall tables (number -> name) ----------------------------------------
_X86_64 = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
    6: "lstat", 8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap",
    12: "brk", 16: "ioctl", 17: "pread64", 18: "pwrite64", 19: "readv",
    20: "writev", 21: "access", 22: "pipe", 23: "select", 24: "sched_yield",
    25: "mremap", 26: "msync", 27: "mincore", 28: "madvise", 32: "dup",
    33: "dup2", 35: "nanosleep", 37: "alarm", 38: "setitimer", 39: "getpid",
    40: "sendfile", 41: "socket", 42: "connect", 43: "accept", 44: "sendto",
    45: "recvfrom", 46: "sendmsg", 47: "recvmsg", 48: "shutdown", 49: "bind",
    50: "listen", 52: "getpeername", 53: "socketpair", 54: "setsockopt",
    55: "getsockopt", 56: "clone", 57: "fork", 58: "vfork", 59: "execve",
    60: "exit", 61: "wait4", 62: "kill", 63: "uname", 64: "fcntl", 72: "fcntl",
    78: "getcwd", 79: "chdir", 80: "fchdir", 82: "rename", 83: "mkdir",
    84: "rmdir", 85: "creat", 86: "link", 87: "unlink", 88: "symlink",
    89: "readlink", 90: "chmod", 91: "fchmod", 92: "chown", 93: "fchown",
    96: "umask", 98: "getrlimit", 99: "getrusage", 101: "ptrace", 106: "utime",
    107: "getppid", 120: "clone3", 132: "futex", 135: "uname", 137: "sched_setaffinity",
    138: "sched_getaffinity", 156: "getrandom", 158: "sched_yield", 192: "membarrier",
    202: "futex", 217: "getdents64", 219: "pivot_root", 221: "mknodat",
    222: "mknod", 234: "getdents64", 257: "openat", 258: "mkdirat",
    259: "mknodat", 260: "fchownat", 261: "futimesat", 262: "newfstatat",
    263: "unlinkat", 264: "renameat", 265: "linkat", 266: "symlinkat",
    267: "readlinkat", 268: "fchmodat", 269: "faccessat", 281: "pwritev2",
    293: "pipe2", 294: "prlimit64", 296: "clock_gettime", 297: "futex",
    302: "prlimit64", 304: "pwritev2", 305: "pwritev2", 313: "execveat",
    316: "memfd_create", 318: "getrandom", 322: "execveat", 334: "rseq",
    310: "process_vm_readv", 311: "process_vm_writev",
    424: "pidfd_open", 425: "clone3",
}
_AARCH64 = {
    0: "io_setup", 1: "io_destroy", 16: "io_setup", 17: "io_destroy",
    21: "rmdir", 22: "mount", 23: "dup", 24: "dup3", 25: "fcntl", 28: "fsync",
    29: "ioctl", 34: "mkdirat", 35: "unlinkat", 36: "symlinkat", 37: "linkat",
    38: "renameat", 40: "mount", 48: "faccessat", 49: "chdir", 50: "fchdir",
    51: "chroot", 52: "fchmod", 53: "fchown", 56: "openat", 57: "close",
    59: "pipe2", 60: "quotactl", 61: "getdents64", 62: "lseek", 63: "read",
    64: "write", 65: "readv", 66: "writev", 67: "pread64", 68: "pwrite64",
    71: "sendfile", 72: "pselect6", 73: "ppoll", 74: "signalfd", 75: "vmsplice",
    76: "splice", 77: "tee", 78: "readlinkat", 79: "newfstatat", 80: "fstat",
    81: "sync", 82: "fsync", 83: "fdatasync", 88: "utimensat", 89: "futimesat",
    90: "chmod", 91: "chown", 92: "chown", 93: "exit", 94: "exit_group",
    96: "set_tid_address", 97: "uname", 98: "futex", 101: "nanosleep",
    103: "clock_settime", 113: "clock_gettime", 115: "clock_nanosleep",
    124: "sched_yield", 129: "kill", 131: "tgkill", 153: "times", 160: "uname",
    163: "getrlimit", 164: "setrlimit", 166: "umask", 167: "prctl",
    169: "gettimeofday", 172: "getpid", 173: "getppid", 178: "gettid",
    198: "socket", 199: "socketpair", 200: "bind", 201: "listen", 202: "accept",
    203: "connect", 204: "getsockname", 205: "getpeername", 206: "sendto",
    207: "recvfrom", 208: "setsockopt", 209: "getsockopt", 210: "shutdown",
    211: "sendmsg", 212: "recvmsg", 214: "brk", 215: "munmap", 216: "mremap",
    217: "clone", 220: "clone", 221: "execve", 222: "mmap", 226: "mprotect",
    227: "msync", 232: "mincore", 233: "madvise", 260: "wait4",
    261: "prlimit64", 270: "process_vm_readv", 271: "process_vm_writev",
    278: "getrandom", 279: "memfd_create", 280: "bpf",
    281: "execveat", 283: "userfaultfd", 291: "openat2", 307: "pidfd_open",
    326: "rseq", 435: "clone3",
}

SPEC: dict[str, tuple[tuple[str, str], ...]] = {
    "read": (("fd", "fd"), ("buf", "ptr"), ("count", "u64")),
    "write": (("fd", "fd"), ("buf", "ptr"), ("count", "u64")),
    "fstat": (("fd", "fd"), ("statbuf", "ptr")),
    "pread64": (("fd", "fd"), ("buf", "ptr"), ("count", "u64"), ("offset", "u64")),
    "pwrite64": (("fd", "fd"), ("buf", "ptr"), ("count", "u64"), ("offset", "u64")),
    "readv": (("fd", "fd"), ("iov", "ptr"), ("iovcnt", "int")),
    "writev": (("fd", "fd"), ("iov", "ptr"), ("iovcnt", "int")),
    "getdents64": (("fd", "fd"), ("buf", "ptr"), ("count", "u64")),
    "dup": (("oldfd", "fd"),),
    "dup2": (("oldfd", "fd"), ("newfd", "fd")),
    "dup3": (("oldfd", "fd"), ("newfd", "fd"), ("flags", "u64")),
    "sendfile": (("out_fd", "fd"), ("in_fd", "fd"), ("offset", "ptr"), ("count", "u64")),
    "ioctl": (("fd", "fd"), ("request", "u64"), ("arg", "ptr")),
    "socketpair": (("domain", "af"), ("type", "socktype"), ("protocol", "int"), ("sv", "ptr")),
    "process_vm_readv": (("pid", "int"), ("lvec", "ptr"), ("liovcnt", "int"), ("rvec", "ptr"), ("riovcnt", "int"), ("flags", "u64")),
    "process_vm_writev": (("pid", "int"), ("lvec", "ptr"), ("liovcnt", "int"), ("rvec", "ptr"), ("riovcnt", "int"), ("flags", "u64")),
    "open": (("path", "str"), ("flags", "open_flags"), ("mode", "u64")),
    "openat": (("dirfd", "int"), ("path", "str"), ("flags", "open_flags"), ("mode", "u64")),
    "close": (("fd", "fd"),),
    "readlink": (("path", "str"), ("buf", "ptr"), ("bufsize", "u64")),
    "readlinkat": (("dirfd", "int"), ("path", "str"), ("buf", "ptr"), ("bufsize", "u64")),
    "execve": (("path", "str"), ("argv", "ptr"), ("envp", "ptr")),
    "execveat": (("dirfd", "int"), ("path", "str"), ("argv", "ptr"), ("envp", "ptr"), ("flags", "u64")),
    "mkdir": (("path", "str"), ("mode", "u64")),
    "mkdirat": (("dirfd", "int"), ("path", "str"), ("mode", "u64")),
    "rmdir": (("path", "str"),),
    "unlink": (("path", "str"),),
    "unlinkat": (("dirfd", "int"), ("path", "str"), ("flags", "u64")),
    "rename": (("oldpath", "str"), ("newpath", "str")),
    "renameat": (("olddirfd", "int"), ("oldpath", "str"), ("newdirfd", "int"), ("newpath", "str")),
    "symlink": (("target", "str"), ("linkpath", "str")),
    "link": (("oldpath", "str"), ("newpath", "str")),
    "chmod": (("path", "str"), ("mode", "u64")),
    "chown": (("path", "str"), ("uid", "int"), ("gid", "int")),
    "access": (("path", "str"), ("mode", "u64")),
    "faccessat": (("dirfd", "int"), ("path", "str"), ("mode", "u64"), ("flags", "u64")),
    "stat": (("path", "str"), ("statbuf", "ptr")),
    "lstat": (("path", "str"), ("statbuf", "ptr")),
    "newfstatat": (("dirfd", "int"), ("path", "str"), ("statbuf", "ptr"), ("flags", "u64")),
    "chdir": (("path", "str"),),
    "getcwd": (("buf", "ptr"), ("size", "u64")),
    "truncate": (("path", "str"), ("length", "u64")),
    "ftruncate": (("fd", "fd"), ("length", "u64")),
    "mmap": (("addr", "ptr"), ("length", "u64"), ("prot", "prot"), ("flags", "mmap_flags"), ("fd", "int"), ("offset", "u64")),
    "mprotect": (("addr", "ptr"), ("length", "u64"), ("prot", "prot")),
    "munmap": (("addr", "ptr"), ("length", "u64")),
    "madvise": (("addr", "ptr"), ("length", "u64"), ("advice", "u64")),
    "mremap": (("old_addr", "ptr"), ("old_size", "u64"), ("new_size", "u64"), ("flags", "u64")),
    "socket": (("domain", "af"), ("type", "socktype"), ("protocol", "int")),
    "connect": (("fd", "fd"), ("sockaddr", "sockaddr"), ("len", "u64")),
    "bind": (("fd", "fd"), ("sockaddr", "sockaddr"), ("len", "u64")),
    "accept": (("fd", "fd"), ("sockaddr", "sockaddr"), ("len", "u64")),
    "accept4": (("fd", "fd"), ("sockaddr", "sockaddr"), ("len", "u64"), ("flags", "u64")),
    "sendto": (("fd", "fd"), ("buf", "ptr"), ("len", "u64"), ("flags", "u64"), ("sockaddr", "sockaddr"), ("addrlen", "u64")),
    "recvfrom": (("fd", "fd"), ("buf", "ptr"), ("len", "u64"), ("flags", "u64"), ("sockaddr", "sockaddr"), ("addrlen", "u64")),
    "sendmsg": (("fd", "fd"), ("msghdr", "ptr"), ("flags", "u64")),
    "recvmsg": (("fd", "fd"), ("msghdr", "ptr"), ("flags", "u64")),
    "shutdown": (("fd", "fd"), ("how", "int")),
    "listen": (("fd", "fd"), ("backlog", "int")),
    "setsockopt": (("fd", "fd"), ("level", "int"), ("optname", "int"), ("optval", "ptr"), ("optlen", "u64")),
    "clone": (("flags", "clone_flags"), ("stack", "ptr")),
    "clone3": (("cl_args", "ptr"), ("size", "u64")),
    "fork": (),
    "vfork": (),
    "ptrace": (("request", "ptrace_req"), ("pid", "int"), ("addr", "ptr"), ("data", "ptr")),
    "nanosleep": (("req", "ptr"), ("rem", "ptr")),
    "clock_nanosleep": (("clockid", "int"), ("flags", "int"), ("req", "ptr"), ("rem", "ptr")),
    "futex": (("uaddr", "ptr"), ("op", "futex_op"), ("val", "int"), ("timeout", "ptr")),
    "kill": (("pid", "int"), ("sig", "signal")),
    "tgkill": (("tgid", "int"), ("tid", "int"), ("sig", "signal")),
    "memfd_create": (("name", "str"), ("flags", "u64")),
    "getrandom": (("buf", "ptr"), ("count", "u64"), ("flags", "u64")),
    "uname": (("uts", "ptr"),),
    "gettimeofday": (("tv", "ptr"), ("tz", "ptr")),
    "clock_gettime": (("clockid", "int"), ("tp", "ptr")),
    "prctl": (("option", "prctl_op"), ("arg2", "u64"), ("arg3", "u64"), ("arg4", "u64"), ("arg5", "u64")),
    "openat2": (("dirfd", "int"), ("path", "str"), ("how", "ptr"), ("size", "u64")),
}

# fd-path resolution for these syscalls at exit
_FD_PATH_RESOLVE = {"read", "write", "close", "fstat", "ftruncate", "fcntl", "fsync",
                    "fdatasync", "readv", "writev", "dup", "dup2", "dup3", "lseek",
                    "sendto", "recvfrom", "connect", "bind", "accept", "accept4",
                    "sendmsg", "recvmsg", "shutdown", "listen", "setsockopt", "getsockopt",
                    "pread64", "pwrite64", "getdents64", "sendfile", "ioctl"}


def _prot_str(prot: int) -> str:
    if prot == _PROT_NONE:
        return "NONE"
    return "".join(_PROT.get(b, "?") for b in (0x1, 0x2, 0x4) if prot & b)


def _open_flags(f: int) -> str:
    acc = {0: "RDONLY", _O_WRONLY: "WRONLY", _O_RDWR: "RDWR"}.get(f & 3, "?")
    out = [acc]
    if f & _O_CREAT:
        out.append("CREAT")
    if f & _O_EXCL:
        out.append("EXCL")
    if f & _O_APPEND:
        out.append("APPEND")
    if f & _O_TRUNC:
        out.append("TRUNC")
    if f & _O_DIRECTORY:
        out.append("DIRECTORY")
    return "|".join(out)


def _sockaddr(family: int, raw: bytes) -> str:
    if family == _socket.AF_INET and len(raw) >= 8:
        port = (raw[2] << 8) | raw[3]
        addr = _socket.inet_ntoa(raw[4:8])
        return f"inet {addr}:{port}"
    if family == _socket.AF_INET6 and len(raw) >= 24:
        port = (raw[2] << 8) | raw[3]
        addr = _socket.inet_ntop(_socket.AF_INET6, raw[8:24])
        return f"inet6 [{addr}]:{port}"
    if family == _socket.AF_UNIX:
        try:
            name = raw[2:].split(b"\0", 1)[0].decode("utf-8", "replace")
        except Exception:
            name = "?"
        return f"unix:{name}"
    return f"af={family}"


class _PTSI_Entry(ctypes.Structure):
    _fields_ = [("nr", ctypes.c_uint64), ("args", ctypes.c_uint64 * 6)]


class _PTSI_Exit(ctypes.Structure):
    _fields_ = [("rval", ctypes.c_int64), ("is_error", ctypes.c_uint8)]


class _PTSI_Payload(ctypes.Union):
    _fields_ = [("entry", _PTSI_Entry), ("exit", _PTSI_Exit)]


class _PtraceSyscallInfo(ctypes.Structure):
    _fields_ = [
        ("op", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
        ("arch", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("stack_pointer", ctypes.c_uint64),
        ("payload", _PTSI_Payload),
    ]


class _SyscallInfo:
    __slots__ = ("stage", "nr", "args", "rval", "is_error")

    def __init__(self, stage: str, nr: int, args: tuple[int, ...], rval: int, is_error: bool) -> None:
        self.stage = stage
        self.nr = nr
        self.args = args
        self.rval = rval
        self.is_error = is_error


class _Regs:
    __slots__ = ("nr", "args", "ret")

    def __init__(self, nr: int, args: tuple[int, ...], ret: int) -> None:
        self.nr = nr
        self.args = args
        self.ret = ret


def _libc() -> ctypes.CDLL:
    libc = ctypes.CDLL(None, use_errno=True)  # type: ignore[attr-defined]
    libc.ptrace.restype = ctypes.c_long  # type: ignore[attr-defined]
    libc.ptrace.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]  # type: ignore[attr-defined]
    return libc


class _UserRegsX64(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulong), ("r14", ctypes.c_ulong), ("r13", ctypes.c_ulong),
        ("r12", ctypes.c_ulong), ("rbp", ctypes.c_ulong), ("rbx", ctypes.c_ulong),
        ("r11", ctypes.c_ulong), ("r10", ctypes.c_ulong), ("r9", ctypes.c_ulong),
        ("r8", ctypes.c_ulong), ("rax", ctypes.c_ulong), ("rcx", ctypes.c_ulong),
        ("rdx", ctypes.c_ulong), ("rsi", ctypes.c_ulong), ("rdi", ctypes.c_ulong),
        ("orig_rax", ctypes.c_ulong), ("rip", ctypes.c_ulong), ("cs", ctypes.c_ulong),
        ("eflags", ctypes.c_ulong), ("rsp", ctypes.c_ulong), ("ss", ctypes.c_ulong),
        ("fs_base", ctypes.c_ulong), ("gs_base", ctypes.c_ulong), ("ds", ctypes.c_ulong),
        ("es", ctypes.c_ulong), ("fs", ctypes.c_ulong), ("gs", ctypes.c_ulong),
    ]


class _UserRegsArm64(ctypes.Structure):
    _fields_ = [
        ("regs", ctypes.c_ulong * 31),
        ("sp", ctypes.c_ulong),
        ("pc", ctypes.c_ulong),
        ("pstate", ctypes.c_ulong),
    ]


class _Arch:
    name = "unknown"

    def read_regs(self, pid: int) -> _Regs:  # pragma: no cover - abstract
        raise NotImplementedError

    def regs_type(self) -> type[ctypes.Structure]:  # pragma: no cover - abstract
        raise NotImplementedError


class _ArchX64(_Arch):
    name = "x86_64"

    def regs_type(self) -> type[ctypes.Structure]:
        return _UserRegsX64

    def read_regs(self, pid: int) -> _Regs:
        regs = _UserRegsX64()
        libc.ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs))
        return _Regs(regs.orig_rax, (regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9), regs.rax)


class _ArchArm64(_Arch):
    name = "aarch64"

    def regs_type(self) -> type[ctypes.Structure]:
        return _UserRegsArm64

    def read_regs(self, pid: int) -> _Regs:
        regs = _UserRegsArm64()
        libc.ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs))
        args = tuple(int(regs.regs[i]) for i in range(5))
        return _Regs(int(regs.regs[8]), args, int(regs.regs[0]))


def _detect_arch() -> _Arch:
    machine = os.uname().machine
    if machine in ("x86_64", "amd64"):
        return _ArchX64()
    if machine in ("aarch64", "arm64"):
        return _ArchArm64()
    raise RuntimeError(f"unsupported architecture: {machine}")


libc = _libc()
_WORD = ctypes.sizeof(ctypes.c_void_p)
_ULONG = ctypes.c_ulong


def _peek_word(pid: int, addr: int) -> int | None:
    if addr <= 0:
        return None
    errno_ctypes = ctypes.get_errno()
    val = libc.ptrace(PTRACE_PEEKDATA, pid, ctypes.c_void_p(addr), 0)
    if val == -1 and ctypes.get_errno() != errno_ctypes:
        return None
    return val & 0xFFFFFFFFFFFFFFFF


def _read_bytes(pid: int, addr: int, n: int) -> bytes:
    if addr <= 0 or n <= 0:
        return b""
    n = min(n, 65536)
    out = bytearray()
    for off in range(0, n, _WORD):
        word = _peek_word(pid, addr + off)
        if word is None:
            break
        take = min(_WORD, n - off)
        out.extend((word & 0xFFFFFFFFFFFFFFFF).to_bytes(_WORD, "little")[:take])
    return bytes(out)


def _read_cstring(pid: int, addr: int, maxlen: int = cfg.MAX_PATH_LEN) -> str | None:
    if addr <= 0:
        return None
    raw = bytearray()
    for off in range(0, maxlen, _WORD):
        word = _peek_word(pid, addr + off)
        if word is None:
            break
        chunk = word.to_bytes(_WORD, "little")
        for b in chunk:
            if b == 0:
                return raw.decode("utf-8", "replace")
            raw.append(b)
    return raw.decode("utf-8", "replace")


def _decode_arg(kind: str, value: int, ctx: _TraceCtx) -> Any:
    if kind == "str":
        return _read_cstring(ctx.pid, value)
    if kind == "fd":
        return int(value)
    if kind == "int":
        return int(value)
    if kind == "u64":
        return int(value)
    if kind == "ptr":
        return f"0x{value:x}" if value else "null"
    if kind == "prot":
        return _prot_str(int(value))
    if kind == "mmap_flags":
        f = int(value)
        flags = []
        if f & _MAP_SHARED:
            flags.append("SHARED")
        if f & _MAP_PRIVATE:
            flags.append("PRIVATE")
        if f & _MAP_FIXED:
            flags.append("FIXED")
        if f & _MAP_GROWSDOWN:
            flags.append("GROWSDOWN")
        if f & _MAP_EXEC:
            flags.append("EXEC")
        if f & _MAP_ANON:
            flags.append("ANON")
        return "|".join(flags) or "0"
    if kind == "open_flags":
        return _open_flags(int(value))
    if kind == "af":
        return f"{int(value)} ({_AF_NAMES.get(int(value), '?')})"
    if kind == "socktype":
        return f"{int(value)} ({_SOCK_NAMES.get(int(value), '?')})"
    if kind == "sockaddr":
        return ""
    if kind == "ptrace_req":
        v = int(value)
        return f"{v} ({_PTRACE_REQ.get(v, '?')})"
    if kind == "signal":
        try:
            return f"{int(value)} ({signal.Signals(value).name})"
        except Exception:
            return str(int(value))
    if kind == "clone_flags":
        f = int(value)
        out = []
        for bit, nm in ((0x100, "VM"), (0x200, "FS"), (0x400, "FILES"), (0x800, "SIGHAND"),
                        (0x40000, "THREAD"), (0x800000, "VFORK"), (0x100000, "SETTLS")):
            if f & bit:
                out.append(nm)
        return "|".join(out) or "0"
    if kind == "futex_op":
        op = int(value) & 0x7F
        return f"{op}"
    if kind == "prctl_op":
        return f"{int(value)}"
    return str(int(value))


class _TraceCtx:
    def __init__(self, pid: int) -> None:
        self.pid = pid


class LinuxTracer:
    """Trace a command (argv) to completion and return recorded syscalls."""

    def __init__(
        self,
        argv: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float = cfg.DEFAULT_TIMEOUT,
        capture_io: bool = cfg.DEFAULT_IO_CAPTURE,
        io_preview: int = cfg.MAX_IO_PREVIEW,
    ) -> None:
        if not argv:
            raise ValueError("argv must not be empty")
        self.argv = argv
        self.cwd = cwd
        self.env = env
        self.timeout = timeout
        self.capture_io = capture_io
        self.io_preview = io_preview
        self.arch = _detect_arch()
        self.table = _X86_64 if self.arch.name == "x86_64" else _AARCH64
        self._in_syscall: dict[int, bool] = {}

    # -- helpers --------------------------------------------------------------
    def _name(self, nr: int) -> str:
        return self.table.get(nr, f"syscall{nr}")

    def _fd_path(self, pid: int, fd: int) -> str | None:
        if fd < 0:
            return None
        try:
            return os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            return None

    def _decode_sockaddr(self, pid: int, addr: int, addrlen: int) -> str | None:
        if addr <= 0 or addrlen <= 0:
            return None
        raw = _read_bytes(pid, addr, min(addrlen, 64))
        if len(raw) < 2:
            return None
        return _sockaddr(raw[0] | (raw[1] << 8), raw)

    # -- event assembly -------------------------------------------------------
    def _emit(self, seq: int, pid: int, tid: int, ts: float, nr: int, args: dict[str, Any],
              ret: int | None, err: str | None, info: dict[str, Any]) -> SyscallEvent:
        return SyscallEvent(
            seq=seq, pid=pid, tid=tid, ts=ts, syscall=self._name(nr), nr=nr,
            args=args, ret=ret, err=err, info=info, arch=self.arch.name,
        )

    # -- syscall info ---------------------------------------------------------
    def _syscall_info(self, pid: int) -> _SyscallInfo | None:
        """Prefer PTRACE_GET_SYSCALL_INFO (kernel >= 5.3); fall back to regs."""
        info = _PtraceSyscallInfo()
        n = libc.ptrace(PTRACE_GET_SYSCALL_INFO, pid, ctypes.sizeof(info), ctypes.byref(info))
        if n > 0:
            if info.op == _SYS_INFO_ENTRY:
                return _SyscallInfo("entry", int(info.payload.entry.nr),
                                    tuple(int(a) for a in info.payload.entry.args), 0, False)
            if info.op == _SYS_INFO_EXIT:
                return _SyscallInfo("exit", 0, (), int(info.payload.exit.rval), bool(info.payload.exit.is_error))
            return None
        # fallback: toggle per-process state (entry then exit)
        regs = self.arch.read_regs(pid)
        in_sys = self._in_syscall[pid]
        if in_sys:
            self._in_syscall[pid] = False
            return _SyscallInfo("exit", 0, (), int(regs.ret), int(regs.ret) < 0)
        self._in_syscall[pid] = True
        return _SyscallInfo("entry", int(regs.nr), regs.args, 0, False)

    # -- trace loop -----------------------------------------------------------
    def run(self) -> tuple[list[SyscallEvent], int | None, list[str], bool]:
        """Run the trace; returns (events, exit_code, signals, timed_out)."""

        env = os.environ.copy()
        if self.env:
            env.update(self.env)

        pid = os.fork()
        if pid == 0:
            # ---- child ----
            try:
                libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
                if self.cwd:
                    os.chdir(self.cwd)
                os.execvpe(self.argv[0], self.argv, env)
            except Exception:  # pragma: no cover
                os._exit(255)

        # ---- parent ----
        events: list[SyscallEvent] = []
        exit_code: int | None = None
        signals: list[str] = []
        timed_out = False

        options = (
            _PTRACE_O_TRACEFORK | _PTRACE_O_TRACEVFORK | _PTRACE_O_TRACECLONE
            | _PTRACE_O_TRACEEXEC | _PTRACE_O_TRACEEXIT | _PTRACE_O_EXITKILL
        )
        traced: set[int] = set()
        pending_entry: dict[int, dict[str, Any]] = {}
        seq = 0
        start = time.monotonic()
        deadline = start + self.timeout

        def continue_all(sig: int = 0) -> None:
            for t in list(traced):
                with contextlib.suppress(OSError):
                    libc.ptrace(PTRACE_SYSCALL, t, 0, sig)

        try:
            _, status = os.waitpid(pid, os.WUNTRACED)
            if not os.WIFSTOPPED(status):
                raise RuntimeError("tracee failed to start")
            libc.ptrace(PTRACE_SETOPTIONS, pid, 0, options)
            traced.add(pid)
            continue_all()

            while traced:
                now = time.monotonic()
                if now >= deadline:
                    timed_out = True
                    for t in list(traced):
                        with contextlib.suppress(ProcessLookupError):
                            os.kill(t, signal.SIGKILL)
                    # reap stragglers briefly
                    end = time.monotonic() + 0.5
                    while traced and time.monotonic() < end:
                        wpid, _ = os.waitpid(-1, os.WNOHANG)
                        if wpid <= 0:
                            time.sleep(0.002)
                            continue
                        traced.discard(wpid)
                        pending_entry.pop(wpid, None)
                    break

                wpid, status = os.waitpid(-1, os.WNOHANG | os.WUNTRACED)
                if wpid <= 0:
                    time.sleep(0.001)
                    continue

                if os.WIFEXITED(status):
                    code = os.WEXITSTATUS(status)
                    if wpid == pid:
                        exit_code = code
                    traced.discard(wpid)
                    pending_entry.pop(wpid, None)
                    continue
                if os.WIFSIGNALED(status):
                    sig = os.WTERMSIG(status)
                    if wpid == pid:
                        signals.append(f"killed by signal {sig}")
                    traced.discard(wpid)
                    pending_entry.pop(wpid, None)
                    continue
                if not os.WIFSTOPPED(status):
                    continue

                sig = os.WSTOPSIG(status)
                event = (status >> 16) & 0xFFFF

                if sig == SIGTRAP and event == _PTRACE_EVENT_EXEC:
                    libc.ptrace(PTRACE_SYSCALL, wpid, 0, 0)
                    continue
                if sig == SIGTRAP and event == _PTRACE_EVENT_EXIT:
                    libc.ptrace(PTRACE_SYSCALL, wpid, 0, 0)
                    continue
                if sig == SIGTRAP and event in (_PTRACE_EVENT_FORK, _PTRACE_EVENT_VFORK, _PTRACE_EVENT_CLONE):
                    newpid = ctypes.c_ulong(0)
                    libc.ptrace(PTRACE_GETEVENTMSG, wpid, 0, ctypes.byref(newpid))
                    libc.ptrace(PTRACE_SETOPTIONS, int(newpid.value), 0, options)
                    traced.add(int(newpid.value))
                    libc.ptrace(PTRACE_SYSCALL, wpid, 0, 0)
                    continue
                if sig == SIGSTOP and wpid != pid:
                    libc.ptrace(PTRACE_SYSCALL, wpid, 0, 0)
                    continue
                if sig != SIGTRAP and sig != SIG_SYSCALL:
                    signals.append(f"signal {sig} to pid {wpid}")
                    libc.ptrace(PTRACE_SYSCALL, wpid, 0, sig)
                    continue

                s_info = self._syscall_info(wpid)
                if s_info is None:
                    libc.ptrace(PTRACE_SYSCALL, wpid, 0, 0)
                    continue
                if s_info.stage == "exit":
                    # syscall exit
                    pending = pending_entry.pop(wpid, None)
                    if pending is None:
                        libc.ptrace(PTRACE_SYSCALL, wpid, 0, 0)
                        continue
                    name = pending["name"]
                    args = pending["args"]
                    info = dict(pending["info"])
                    ret: int | None = None
                    err = None
                    if s_info.is_error and s_info.rval < 0:
                        r = -s_info.rval
                        err = errno.errorcode.get(r, f"errno{r}")
                    else:
                        ret = int(s_info.rval)
                    if name in _FD_PATH_RESOLVE:
                        fd = args.get("fd")
                        if isinstance(fd, int) and fd >= 0:
                            p = self._fd_path(wpid, fd)
                            if p:
                                info["fd_path"] = p
                    seq += 1
                    events.append(self._emit(seq, wpid, wpid, time.monotonic(), pending["nr"], args, ret, err, info))
                    libc.ptrace(PTRACE_SYSCALL, wpid, 0, 0)
                    continue

                # syscall entry
                nr = s_info.nr
                sargs = s_info.args
                name = self._name(nr)
                entry_args: dict[str, Any] = {}
                entry_info: dict[str, Any] = {}
                ctx = _TraceCtx(wpid)
                spec = SPEC.get(name)
                if spec is not None:
                    for i, (argname, kind) in enumerate(spec):
                        val = sargs[i] if i < len(sargs) else 0
                        decoded = _decode_arg(kind, val, ctx)
                        if decoded != "":
                            entry_args[argname] = decoded
                        else:
                            # empty means a sockaddr we must decode with extra context
                            if kind == "sockaddr":
                                if name in ("connect", "bind", "accept", "accept4"):
                                    addrlen = entry_args.get("len")
                                    raw = _read_bytes(wpid, val, min(int(addrlen) if addrlen else 16, 64))
                                    if len(raw) >= 2:
                                        entry_info["sock"] = _sockaddr(raw[0] | (raw[1] << 8), raw)
                                        entry_args[argname] = entry_info["sock"]
                                elif name in ("sendto", "recvfrom"):
                                    addrlen = entry_args.get("addrlen")
                                    raw = _read_bytes(wpid, val, min(int(addrlen) if addrlen else 16, 64))
                                    if len(raw) >= 2:
                                        entry_info["sock"] = _sockaddr(raw[0] | (raw[1] << 8), raw)
                                        entry_args[argname] = entry_info["sock"]

                # extra decoding that benefits from entry-time memory
                if name in ("write", "read", "sendto", "recvfrom", "pwrite64", "pread64") and self.capture_io:
                    buf = sargs[1]
                    count = int(sargs[2])
                    preview = _read_bytes(wpid, buf, min(count, self.io_preview))
                    if preview:
                        entry_info["io_preview"] = preview.hex(" ")
                if name in ("mmap", "mprotect"):
                    entry_info["region"] = f"0x{sargs[0]:x} len={int(sargs[1])} prot={_prot_str(int(sargs[2]))}"
                if name in ("mmap",):
                    entry_info["anon"] = bool(int(sargs[3]) & _MAP_ANON)
                if name in ("nanosleep", "clock_nanosleep"):
                    req = _read_bytes(wpid, sargs[2] if name == "clock_nanosleep" else sargs[0], 16)
                    if len(req) == 16:
                        sec = int.from_bytes(req[0:8], "little")
                        nsec = int.from_bytes(req[8:16], "little")
                        entry_info["sleep"] = f"{sec}.{nsec:09d}s"
                if name in ("connect",) and "sock" not in entry_info:
                    raw = _read_bytes(wpid, sargs[1], 16)
                    if len(raw) >= 2:
                        entry_info["sock"] = _sockaddr(raw[0] | (raw[1] << 8), raw)
                if name in ("execve",):
                    argv_ptr = sargs[1]
                    if argv_ptr:
                        arg0 = _read_cstring(wpid, _peek_word(wpid, argv_ptr) or 0)
                        if arg0:
                            entry_info["argv0"] = arg0

                pending_entry[wpid] = {"name": name, "nr": nr, "args": entry_args, "info": entry_info}
                libc.ptrace(PTRACE_SYSCALL, wpid, 0, 0)

        finally:
            for t in list(traced):
                with contextlib.suppress(ProcessLookupError):
                    os.kill(t, signal.SIGKILL)

        return events, exit_code, signals, timed_out


__all__ = ["LinuxTracer"]
