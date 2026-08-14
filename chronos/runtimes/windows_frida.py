"""Windows runtime using Frida usermode instrumentation.

Requires a Windows host and the optional ``frida`` extra:

    pip install "chronos[windows]"

Frida hooks the native APIs the sample calls (kernel32 / advapi32 / ws2_32 /
ntdll) and streams behavioral events back. This is observation only — the
script never patches control flow, it only reads arguments and returns.

Isolation notes (see docs/architecture.md): run this runtime from a dedicated
low-privilege account, ideally inside a disposable Windows VM.
"""

from __future__ import annotations

import contextlib
import time

from chronos.events import BehaviorEvent

from .base import Runtime, RuntimeResult

_FRIDA_SCRIPT = r"""
"use strict";

function sockaddrStr(ptr, len) {
    if (ptr.isNull() || len === 0) return null;
    var family = ptr.readU16();
    if (family === 2 && len >= 8) {  // AF_INET
        var port = ptr.add(2).readU16() & 0xffff;
        var addr = ptr.add(4).readU32() >>> 0;
        var ip = ((addr >>> 24) & 0xff) + "." + ((addr >>> 16) & 0xff) + "."
               + ((addr >>> 8) & 0xff) + "." + (addr & 0xff);
        return ip + ":" + port;
    }
    if (family === 23 && len >= 24) {  // AF_INET6
        var port = ptr.add(2).readU16() & 0xffff;
        var ip = ptr.add(8).readUtf8String(32);
        return "[" + ip + "]:" + port;
    }
    return "family=" + family;
}

function protStr(v) {
    var out = [];
    if (v & 0x01) out.push("EXEC");
    if (v & 0x02) out.push("READ");
    if (v & 0x04) out.push("WRITE");
    return out.join("|") || "NONE";
}

function emit(cat, op, target, data) {
    send({ t: "evt", cat: cat, op: op, target: target || "", data: data || {} });
}

// --- ntdll native primitives ---------------------------------------------
var ntdll = Process.getModuleByName("ntdll.dll");

try {
    Interceptor.attach(ntdll.getExportByName("NtAllocateVirtualMemory"), {
        onEnter: function (args) {
            this.size = args[3].readPointer();
            this.prot = args[5].readU32();
            this.commit = args[4].readU32();
            emit("memory", "nt_alloc", "0x" + args[1].readPointer().toString(16),
                 { size: this.size.toInt32(), prot: protStr(this.prot) });
        }
    });
} catch (e) {}

try {
    Interceptor.attach(ntdll.getExportByName("NtProtectVirtualMemory"), {
        onEnter: function (args) {
            var prot = args[3].readU32();
            emit("memory", "nt_protect", "0x" + args[1].readPointer().toString(16),
                 { prot: protStr(prot) });
        }
    });
} catch (e) {}

try {
    Interceptor.attach(ntdll.getExportByName("NtWriteVirtualMemory"), {
        onEnter: function (args) {
            var n = args[3].toInt32();
            emit("memory", "nt_write", "0x" + args[1].toString(16),
                 { size: n, remote: args[0].toInt32() !== -1 });
        }
    });
} catch (e) {}

try {
    Interceptor.attach(ntdll.getExportByName("NtCreateThreadEx"), {
        onEnter: function () {
            emit("process", "remote_thread", "", {});
        }
    });
} catch (e) {}

try {
    Interceptor.attach(ntdll.getExportByName("NtQueryInformationProcess"), {
        onEnter: function (args) {
            if (args[1].toInt32() === 7 || args[1].toInt32() === 30) {  // ProcessDebugPort / DebugObjectHandle
                emit("debugger", "query_debug", "ProcessDebugPort", { info_class: args[1].toInt32() });
            }
        }
    });
} catch (e) {}

// --- kernel32 wrappers -----------------------------------------------------
var kernel32 = Process.getModuleByName("kernel32.dll");

try {
    Interceptor.attach(kernel32.getExportByName("VirtualAlloc"), {
        onEnter: function (args) {
            emit("memory", "alloc", "0x" + args[0].toString(16),
                 { size: args[1].toInt32(), prot: protStr(args[3].toInt32()) });
        }
    });
} catch (e) {}

try {
    Interceptor.attach(kernel32.getExportByName("VirtualProtect"), {
        onEnter: function (args) {
            emit("memory", "protect", "0x" + args[0].toString(16),
                 { prot: protStr(args[2].toInt32()) });
        }
    });
} catch (e) {}

try {
    Interceptor.attach(kernel32.getExportByName("WriteProcessMemory"), {
        onEnter: function (args) {
            emit("process", "write_remote", "pid=" + args[0].toInt32(),
                 { size: args[3].toInt32() });
        }
    });
} catch (e) {}

try {
    Interceptor.attach(kernel32.getExportByName("CreateRemoteThread"), {
        onEnter: function () {
            emit("process", "remote_thread", "", {});
        }
    });
} catch (e) {}

function hookCreateFile(name, wide) {
    try {
        Interceptor.attach(kernel32.getExportByName(name), {
            onEnter: function (args) {
                var path = wide ? args[0].readUtf16String() : args[0].readCString();
                var access = args[1].toInt32() & 3;
                var write = access !== 0;
                emit("filesystem", write ? "open_write" : "open_read", path || "?", {});
            }
        });
    } catch (e) {}
}
hookCreateFile("CreateFileW", true);
hookCreateFile("CreateFileA", false);

try {
    Interceptor.attach(kernel32.getExportByName("WriteFile"), {
        onEnter: function (args) {
            emit("filesystem", "write", "", { size: args[2].toInt32() });
        }
    });
} catch (e) {}

try {
    Interceptor.attach(kernel32.getExportByName("DeleteFileW"), {
        onEnter: function (args) {
            emit("filesystem", "delete", args[0].readUtf16String() || "?", {});
        }
    });
} catch (e) {}

try {
    Interceptor.attach(kernel32.getExportByName("IsDebuggerPresent"), {
        onEnter: function () {
            emit("debugger", "is_debugger_present", "", {});
        }
    });
} catch (e) {}

try {
    Interceptor.attach(kernel32.getExportByName("Sleep"), {
        onEnter: function (args) {
            emit("io", "sleep", "", { ms: args[0].toInt32() });
        }
    });
} catch (e) {}

try {
    Interceptor.attach(kernel32.getExportByName("GetProcAddress"), {
        onEnter: function () {
            emit("io", "resolve_api", "", {});
        }
    });
} catch (e) {}

// --- registry ---------------------------------------------------------------
try {
    Interceptor.attach(Process.getModuleByName("advapi32.dll").getExportByName("RegSetValueExW"), {
        onEnter: function (args) {
            emit("registry", "set_value", "", {});
        }
    });
} catch (e) {}

// --- sockets ----------------------------------------------------------------
var ws2_32 = Process.getModuleByName("ws2_32.dll");
function hookConn(name, op) {
    try {
        Interceptor.attach(ws2_32.getExportByName(name), {
            onEnter: function (args) {
                var dst = sockaddrStr(args[1], args[2].toInt32());
                emit("network", op, dst || "", {});
            }
        });
    } catch (e) {}
}
hookConn("connect", "connect");
hookConn("sendto", "sendto");
hookConn("recvfrom", "recvfrom");
"""


class WindowsFridaRuntime(Runtime):
    name = "windows-frida"
    description = "Spawn a Windows sample and hook native APIs with Frida."

    def run(self, config) -> RuntimeResult:  # type: ignore[no-untyped-def]
        try:
            import frida  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "frida is required for windows-frida: pip install 'chronos[windows]'"
            ) from exc

        argv = getattr(self, "argv", None)
        if not argv:
            raise ValueError("windows-frida runtime requires an argv (sample first)")

        start = time.monotonic()
        behaviors: list[BehaviorEvent] = []
        seq = 0

        def on_message(message: dict, _data: bytes | None) -> None:
            nonlocal seq
            if message.get("type") != "send":
                return
            payload = message.get("payload", {})
            if not isinstance(payload, dict) or payload.get("t") != "evt":
                return
            seq += 1
            behaviors.append(
                BehaviorEvent(
                    seq=seq,
                    pid=payload.get("pid", 0),
                    tid=payload.get("tid", 0),
                    ts=time.monotonic(),
                    category=str(payload.get("cat", "")),
                    op=str(payload.get("op", "")),
                    target=str(payload.get("target", "")),
                    data=payload.get("data") or {},
                )
            )

        device = frida.get_local_device()
        pid = device.spawn([argv[0], *argv[1:]])
        session = device.attach(pid)
        script = session.create_script(_FRIDA_SCRIPT)
        script.on("message", on_message)
        script.load()
        device.resume(pid)

        timed_out = False
        try:
            deadline = time.monotonic() + config.timeout
            while time.monotonic() < deadline:
                try:
                    proc = device.get_process(pid)
                except frida.ProcessNotFoundError:  # type: ignore[attr-defined]
                    break
                if not proc:
                    break
                time.sleep(0.05)
            else:
                timed_out = True
        finally:
            with contextlib.suppress(Exception):
                device.kill(pid)
            with contextlib.suppress(Exception):
                script.unload()
                session.detach()

        return RuntimeResult(
            sample=argv[0],
            behaviors=behaviors,
            timed_out=timed_out,
            duration=time.monotonic() - start,
        )
