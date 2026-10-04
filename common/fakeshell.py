"""
HoneyBot-IoT — higher-interaction fake shell (shared by SSH and Telnet).

* JSON-like in-memory filesystem per device (BusyBox / Buildroot style)
* argument-tolerant commands  (`ls`, `ls -la /tmp`, `cat /proc/cpuinfo` …)
* command chains:  a; b && c || d,  pipes into grep/head/tail/wc,  > / >> redirects
* wget / curl / tftp / ftpget:  URL is LOGGED as an IOC, NEVER fetched
* echo -e '\\x7fELF…' > /tmp/x : file content captured with SHA-256
* device commands that read/write the shared Device State (lockctl, sensorctl)

Nothing here ever executes a real process or opens a network connection.
"""

import re
import time
import shlex
import random
import hashlib
import posixpath
from datetime import datetime, timezone

from common.state import STATE

URL_RE = re.compile(r"""((?:https?|ftp|tftp)://[^\s'";|&<>`)]+)""", re.I)
HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

BIN_NAMES = ("ash busybox cat chmod chown cp date dd df dmesg echo egrep false grep gunzip "
             "gzip hostname kill ln login ls mkdir mknod mount mv netstat nproc ping ps pwd "
             "rm rmdir sed sh sleep sync tar touch true umount uname vi").split()
SBIN_NAMES = "ifconfig init insmod lsmod reboot route syslogd telnetd udhcpc watchdog".split()
USRBIN_NAMES = ("awk basename clear crontab cut env expr find free head id killall "
                "md5sum nohup passwd tail tee test tftp top tr uptime wc wget which whoami "
                "xargs ftpget").split()

PROFILES = {
    "smartlock": {
        "hostname": "smartlock",
        "arch": "armv7l",
        "kernel": "4.14.98",
        "kernel_build": "#1 SMP PREEMPT Tue Mar 9 11:42:07 CST 2021",
        "cpu": "ARMv7 Processor rev 5 (v7l)",
        "mem_kb": 249416,
        "ip": "192.168.1.100", "mac": "B8:27:EB:4C:21:9A",
        "busybox": "BusyBox v1.31.1 (2021-03-09 11:39:12 CST) multi-call binary.",
        "procs": [("1", "root", "init"), ("212", "root", "/sbin/syslogd -n"),
                  ("240", "root", "/usr/sbin/dropbear -R -p 22"),
                  ("261", "root", "/usr/bin/lockd --config /etc/smartlock/config.json"),
                  ("270", "root", "/usr/bin/mqtt_bridge -h 127.0.0.1"),
                  ("288", "root", "/usr/sbin/lighttpd -f /etc/lighttpd.conf")],
    },
    "sensor": {
        "hostname": "sensor-node",
        "arch": "armv5tejl",
        "kernel": "3.10.14",
        "kernel_build": "#2 PREEMPT Mon Aug 17 09:12:44 UTC 2020",
        "cpu": "ARM926EJ-S rev 5 (v5l)",
        "mem_kb": 61724,
        "ip": "10.0.0.50", "mac": "00:1E:C0:7A:33:0F",
        "busybox": "BusyBox v1.24.1 (2020-08-17 09:10:02 UTC) multi-call binary.",
        "procs": [("1", "root", "init"), ("98", "root", "/sbin/syslogd"),
                  ("120", "root", "/usr/sbin/telnetd -l /bin/login"),
                  ("133", "root", "/usr/bin/sensor_daemon -c /etc/sensor.conf"),
                  ("141", "root", "/usr/bin/modbusd -p 502"),
                  ("150", "root", "/usr/bin/mqtt_pub -i 5")],
    },
}


def _ts():
    return datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")


class FakeShell:
    def __init__(self, device, session=None, user="root", state=STATE):
        self.device = device
        self.p = PROFILES[device]
        self.session = session
        self.user = user
        self.state = state
        self.home = "/root" if user == "root" else f"/home/{user}"
        self.cwd = self.home
        self.started = time.time()
        self.history = []
        self.env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": self.home,
                    "USER": user, "SHELL": "/bin/sh"}
        self.dirs, self.files, self.dynamic = set(), {}, {}
        self._build_fs()

    # ── filesystem ─────────────────────────────────────────────────────────
    def _build_fs(self):
        p = self.p
        for d in ("/", "/bin", "/sbin", "/etc", "/etc/init.d", "/dev", "/dev/shm", "/proc",
                  "/sys", "/tmp", "/var", "/var/run", "/var/tmp", "/var/log", "/usr",
                  "/usr/bin", "/usr/sbin", "/lib", "/home", "/mnt", "/opt", "/root",
                  f"/home/{self.user}" if self.user != "root" else "/root"):
            self.dirs.add(d)
        elf = "\x7fELF\x01\x01\x01" + "\x00" * 9
        for n in BIN_NAMES:
            self.files[f"/bin/{n}"] = elf
        for n in SBIN_NAMES:
            self.files[f"/sbin/{n}"] = elf
        for n in USRBIN_NAMES:
            self.files[f"/usr/bin/{n}"] = elf
        self.files.update({
            "/etc/hostname": p["hostname"] + "\n",
            "/etc/hosts": f"127.0.0.1\tlocalhost\n{p['ip']}\t{p['hostname']}\n",
            "/etc/passwd": ("root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/bin/false\n"
                            "admin:x:1000:1000:admin:/home/admin:/bin/sh\n"
                            "nobody:x:65534:65534:nobody:/home:/bin/false\n"),
            "/etc/shadow": ("root:$1$Lk2Wq9xz$3sN0eYb1r8cQe6UQmP3gT/:18700:0:99999:7:::\n"
                            "admin:$1$h5Tq0aZ1$8mXq0w1kSx9f7k3QaWl2B.:18700:0:99999:7:::\n"),
            "/etc/issue": "Welcome to Buildroot\n",
            "/etc/os-release": 'NAME=Buildroot\nVERSION=2020.02.9\nID=buildroot\nPRETTY_NAME="Buildroot 2020.02.9"\n',
            "/etc/resolv.conf": "nameserver 192.168.1.1\n",
            "/etc/inittab": "::sysinit:/etc/init.d/rcS\n::respawn:/sbin/getty -L ttyS0 115200 vt100\n",
            "/etc/init.d/rcS": "#!/bin/sh\nfor i in /etc/init.d/S??* ; do $i start; done\n",
            "/proc/version": f"Linux version {p['kernel']} (builder@buildhost) (gcc version 8.4.0) {p['kernel_build']}\n",
            "/proc/mounts": ("rootfs / rootfs rw 0 0\n/dev/root / squashfs ro,relatime 0 0\n"
                             "proc /proc proc rw,relatime 0 0\nsysfs /sys sysfs rw,relatime 0 0\n"
                             "tmpfs /tmp tmpfs rw,relatime 0 0\ntmpfs /dev/shm tmpfs rw,relatime 0 0\n"),
            "/proc/cpuinfo": (f"processor\t: 0\nmodel name\t: {p['cpu']}\nBogoMIPS\t: 38.40\n"
                              "Features\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt\n"
                              "CPU implementer\t: 0x41\nCPU architecture: 7\nCPU variant\t: 0x0\n"
                              "CPU part\t: 0xc07\nCPU revision\t: 5\n\nHardware\t: Generic DT based system\n"
                              f"Revision\t: 0000\nSerial\t\t: {self.state.field(self.device, 'serial', '0000')}\n"),
            "/proc/meminfo": (f"MemTotal:        {p['mem_kb']} kB\nMemFree:         {p['mem_kb']//3} kB\n"
                              f"MemAvailable:    {p['mem_kb']//2} kB\nBuffers:            4120 kB\n"
                              "Cached:            30412 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\n"),
            "/var/log/messages": f"{_ts()} {p['hostname']} syslog.info syslogd started: BusyBox v1.31.1\n",
            "/root/.ash_history": "",
        })
        self.dynamic["/proc/uptime"] = lambda: f"{self._uptime():.2f} {self._uptime()*0.9:.2f}\n"

        if self.device == "smartlock":
            self.dirs.update({"/etc/smartlock", "/var/lib", "/var/lib/smartlock"})
            self.files["/usr/bin/lockctl"] = elf
            self.files["/usr/bin/lockd"] = elf
            self.files["/etc/smartlock/config.json"] = (
                '{\n  "device_id": "SL200-0009A3F1",\n  "cloud": "mqtt://iot.securehome.example:1883",\n'
                f'  "api_token": "{self.state.field("smartlock", "api_token")}",\n'
                '  "auto_lock": true,\n  "admin_pin": "4711"\n}\n')
            self.files["/var/log/lock.log"] = f"{_ts()} lockd: door locked (keypad)\n"
            self.dynamic["/etc/lock_state"] = lambda: self.state.field("smartlock", "lock_state") + "\n"
            self.dynamic["/var/lib/smartlock/battery"] = lambda: self.state.field("smartlock", "battery") + "\n"
        else:
            self.files["/usr/bin/sensorctl"] = elf
            self.files["/usr/bin/sensor_daemon"] = elf
            self.files["/usr/bin/modbusd"] = elf
            self.files["/etc/modbus.conf"] = "slave_id=1\nport=502\nregisters=40001-40010\n"
            self.files["/var/log/sensor.log"] = f"{_ts()} sensor_daemon: polling every 5s\n"
            self.dynamic["/etc/sensor.conf"] = lambda: "".join(
                f"{k}={self.state.field('sensor', k)}\n"
                for k in ("interval", "temp_threshold", "pressure_threshold", "mode"))
            self.dynamic["/proc/sensor"] = lambda: "".join(
                f"{k}: {self.state.field('sensor', k)}\n"
                for k in ("temperature", "pressure", "humidity", "alarm"))

    def _uptime(self):
        return 864000 + (time.time() - self.started) + 3721.4

    def _abs(self, path):
        if not path:
            return self.cwd
        path = path.replace("~", self.home, 1) if path.startswith("~") else path
        return posixpath.normpath(posixpath.join(self.cwd, path)) or "/"

    def _exists(self, p):
        return p in self.dirs or p in self.files or p in self.dynamic

    def _read(self, p):
        if p in self.dynamic:
            return self.dynamic[p]()
        return self.files.get(p)

    def _children(self, d):
        pre = d.rstrip("/") + "/"
        names = set()
        for p in list(self.dirs) + list(self.files) + list(self.dynamic):
            if p != d and p.startswith(pre):
                names.add(p[len(pre):].split("/")[0])
        return sorted(names)

    # ── prompt ─────────────────────────────────────────────────────────────
    @property
    def prompt(self):
        if self.device == "sensor":
            return "# " if self.user == "root" else "$ "
        cwd = "~" if self.cwd == self.home else self.cwd
        return f"{self.user}@{self.p['hostname']}:{cwd}{'#' if self.user == 'root' else '$'} "

    # ── logging helpers ────────────────────────────────────────────────────
    def _log(self, event_type, **kw):
        if self.session is not None:
            self.session.event(event_type, **kw)

    # ── main entry ─────────────────────────────────────────────────────────
    def run(self, line):
        """Execute one input line.  Returns (output, should_exit)."""
        line = line.strip()
        if not line:
            return "", False
        self.history.append(line)
        for url in URL_RE.findall(line):
            self._log("download_attempt", payload=url, url=url, command=line[:500])
        out, exit_ = [], False
        last_ok = True
        for op, segment in self._split_chain(line):
            if op == "&&" and not last_ok:
                continue
            if op == "||" and last_ok:
                continue
            text, ok, ex = self._pipeline(segment)
            last_ok = ok
            if text:
                out.append(text)
            if ex:
                exit_ = True
                break
        result = "\n".join(o.rstrip("\n") for o in out if o is not None)
        if self.session is not None:
            self.session.command(line, output=result)
        return result, exit_

    @staticmethod
    def _split_chain(line):
        parts, cur, op, i, quote = [], "", ";", 0, None
        while i < len(line):
            c = line[i]
            if quote:
                cur += c
                if c == quote:
                    quote = None
            elif c in "'\"":
                quote = c
                cur += c
            elif line.startswith("&&", i) or line.startswith("||", i):
                parts.append((op, cur)); op = line[i:i + 2]; cur = ""; i += 1
            elif c in ";\n":
                parts.append((op, cur)); op = ";"; cur = ""
            elif c == "&" and not (cur.endswith(">") or line.startswith(">", i + 1)):
                # background job – treat as ;
                parts.append((op, cur)); op = ";"; cur = ""
            else:
                cur += c
            i += 1
        parts.append((op, cur))
        return [(o, s.strip()) for o, s in parts if s.strip()]

    def _pipeline(self, segment):
        stages = [s.strip() for s in re.split(r"(?<!\|)\|(?!\|)", segment) if s.strip()]
        data, ok, ex = None, True, False
        for i, st in enumerate(stages):
            data, ok, ex = self._simple(st, stdin=data if i else None)
            if ex:
                break
        return data or "", ok, ex

    def _simple(self, cmdline, stdin=None):
        # redirections (strip trailing  >file  >>file  2>&1  >/dev/null ...)
        redirect, append, discard = None, False, False
        while True:
            m = re.search(r"(\d?)(>>?)\s*(&?\S+)\s*$", cmdline)
            if not m or cmdline[:m.start()].count("'") % 2 or cmdline[:m.start()].count('"') % 2:
                break
            fd, op, target = m.groups()
            cmdline = cmdline[:m.start()].rstrip()
            if fd in ("", "1") and target == "/dev/null":
                discard = True
            elif fd in ("", "1") and not target.startswith("&"):
                redirect, append = target, op == ">>"
        try:
            argv = shlex.split(cmdline, posix=True)
        except ValueError:
            argv = cmdline.split()
        if not argv:
            return "", True, False
        # variable assignment / env prefix
        while argv and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0]):
            k, v = argv.pop(0).split("=", 1)
            self.env[k] = v
        if not argv:
            return "", True, False
        name = posixpath.basename(argv[0])
        args = argv[1:]
        if name == "busybox" and args:
            if args[0].isupper() or args[0] not in self._known():
                return f"{args[0]}: applet not found", False, False
            name, args = args[0], args[1:]
        handler = getattr(self, f"c_{name.replace('-', '_').replace('.', '_')}", None)
        if argv[0].startswith("./") or argv[0].startswith("/tmp/") or argv[0].startswith("/var/"):
            handler = self.c__exec
            args = argv
        if handler is None:
            return self._not_found(argv[0]), False, False
        try:
            res = handler(args, stdin)
        except Exception:
            res = ""
        if isinstance(res, tuple):
            out = res[0]
            ok = res[1] if len(res) > 1 else True
            ex = res[2] if len(res) > 2 else False
        else:
            out, ok, ex = res, True, False
        if redirect:
            self._write(redirect, out or "", append)
            out = ""
        elif discard:
            out = ""
        return out, ok, ex

    def _known(self):
        return {n[2:] for n in dir(self) if n.startswith("c_") and not n.startswith("c__")}

    def _not_found(self, cmd):
        return f"-sh: {cmd}: not found" if self.device == "sensor" else f"-bash: {cmd}: command not found"

    def _write(self, path, content, append=False):
        p = self._abs(path)
        parent = posixpath.dirname(p)
        if parent not in self.dirs:
            return
        if p.startswith("/proc") or p.startswith("/sys"):
            return
        new = (self.files.get(p, "") if append else "") + content
        self.files[p] = new
        data = new.encode("latin-1", "replace")
        self._log("file_write", payload=new[:2000], path=p, size=len(data),
                  sha256=hashlib.sha256(data).hexdigest(), append=append)

    # ── commands ───────────────────────────────────────────────────────────
    def c_exit(self, a, i=None):
        return "logout", True, True
    c_logout = c_exit
    c_quit = c_exit

    def c_true(self, a, i=None): return ""
    def c_false(self, a, i=None): return "", False
    def c_sync(self, a, i=None): return ""
    def c_clear(self, a, i=None): return "\x1b[H\x1b[2J"

    # common Mirai/Gafgyt preamble – real BusyBox shells accept these silently
    def c_enable(self, a, i=None): return ""
    def c_system(self, a, i=None): return ""
    def c_shell(self, a, i=None): return ""
    def c_sh(self, a, i=None):
        if a and a[0] == "-c" and len(a) > 1:
            return self._pipeline(a[1])[0]
        return ""
    c_ash = c_sh
    c_bash = c_sh
    c_linuxshell = c_shell
    def c_cd(self, a, i=None):
        target = self._abs(a[0] if a else self.home)
        if target in self.dirs:
            self.cwd = target
            return ""
        return f"-sh: cd: can't cd to {a[0]}", False

    def c_pwd(self, a, i=None): return self.cwd
    def c_whoami(self, a, i=None): return self.user
    def c_id(self, a, i=None):
        return "uid=0(root) gid=0(root) groups=0(root)" if self.user == "root" else \
            "uid=1000(admin) gid=1000(admin) groups=1000(admin)"

    def c_hostname(self, a, i=None): return self.p["hostname"]

    def c_uname(self, a, i=None):
        p = self.p
        flags = "".join(x[1:] for x in a if x.startswith("-")) or "s"
        if "a" in flags:
            return f"Linux {p['hostname']} {p['kernel']} {p['kernel_build']} {p['arch']} GNU/Linux"
        parts = []
        for f, v in (("s", "Linux"), ("n", p["hostname"]), ("r", p["kernel"]),
                     ("v", p["kernel_build"]), ("m", p["arch"]), ("p", p["arch"]),
                     ("o", "GNU/Linux")):
            if f in flags:
                parts.append(v)
        return " ".join(parts)

    def c_nproc(self, a, i=None): return "1"
    def c_date(self, a, i=None): return _ts()
    def c_uptime(self, a, i=None):
        up = self._uptime()
        return (f" {datetime.now(timezone.utc).strftime('%H:%M:%S')} up {int(up // 86400)} days, "
                f"{int(up % 86400 // 3600)}:{int(up % 3600 // 60):02d},  load average: 0.08, 0.03, 0.01")

    def c_w(self, a, i=None): return self.c_uptime(a) + "\nUSER     TTY      FROM             LOGIN@\nroot     pts/0    -                now"
    def c_history(self, a, i=None):
        return "\n".join(f"  {n+1}  {c}" for n, c in enumerate(self.history))

    def c_echo(self, a, i=None):
        newline = True
        interp = False
        while a and a[0] in ("-n", "-e", "-ne", "-en", "-E"):
            if "n" in a[0]: newline = False
            if "e" in a[0]: interp = True
            a = a[1:]
        s = " ".join(a)
        s = re.sub(r"\$(\w+)", lambda m: self.env.get(m.group(1), ""), s)
        if interp:
            try:
                s = s.encode("latin-1", "backslashreplace").decode("unicode_escape")
            except Exception:
                pass
        return s + ("\n" if newline else "")
    c_printf = c_echo

    def c_export(self, a, i=None):
        for x in a:
            if "=" in x:
                k, v = x.split("=", 1); self.env[k] = v
        return ""

    def c_env(self, a, i=None): return "\n".join(f"{k}={v}" for k, v in self.env.items())

    def c_ls(self, a, i=None):
        flags = "".join(x[1:] for x in a if x.startswith("-"))
        paths = [x for x in a if not x.startswith("-")] or [self.cwd]
        out = []
        for path in paths:
            p = self._abs(path)
            if p in self.files or p in self.dynamic:
                out.append(self._ls_line(p, posixpath.basename(p)) if "l" in flags else path)
                continue
            if p not in self.dirs:
                out.append(f"ls: {path}: No such file or directory")
                continue
            names = self._children(p)
            if "a" not in flags:
                names = [n for n in names if not n.startswith(".")]
            elif "l" not in flags:
                names = [".", ".."] + names
            if len(paths) > 1:
                out.append(f"{path}:")
            if "l" in flags:
                out.append(f"total {len(names) * 4}")
                if "a" in flags:
                    out += [self._ls_line(p, "."), self._ls_line(posixpath.dirname(p), "..")]
                out += [self._ls_line(posixpath.join(p, n), n) for n in names]
            else:
                out.append("  ".join(names))
        return "\n".join(out)

    def _ls_line(self, p, name):
        isdir = p in self.dirs
        size = 0 if isdir else len(self._read(p) or "")
        if p.startswith(("/bin/", "/sbin/", "/usr/bin/")) and not isdir:
            size = 1 if posixpath.basename(p) != "busybox" else 1014812
            perm = "lrwxrwxrwx" if posixpath.basename(p) != "busybox" else "-rwxr-xr-x"
            if perm.startswith("l"):
                return f"{perm}    1 root     root            7 Mar  9  2021 {name} -> busybox"
        else:
            perm = "drwxr-xr-x" if isdir else ("-rwxr-xr-x" if self._is_exec(p) else "-rw-r--r--")
        return f"{perm}    {2 if isdir else 1} root     root     {size:>8} Mar  9  2021 {name}"

    def _is_exec(self, p):
        return getattr(self, "_execs", set()).__contains__(p)

    def c_cat(self, a, i=None):
        files = [x for x in a if not x.startswith("-")]
        if not files:
            return i or ""
        out = []
        for f in files:
            p = self._abs(f)
            if p in self.dirs:
                out.append(f"cat: read error: Is a directory")
            elif self._exists(p):
                out.append(self._read(p) or "")
            else:
                out.append(f"cat: can't open '{f}': No such file or directory")
        return "".join(x if x.endswith("\n") else x + "\n" for x in out)

    def c_head(self, a, i=None):
        n = 10
        files = []
        it = iter(a)
        for x in it:
            if x == "-n": n = int(next(it, 10))
            elif re.match(r"^-\d+$", x): n = int(x[1:])
            else: files.append(x)
        data = self.c_cat(files) if files else (i or "")
        return "\n".join(data.splitlines()[:n])

    def c_tail(self, a, i=None):
        n = 10
        files = []
        it = iter(a)
        for x in it:
            if x == "-n": n = int(next(it, 10))
            elif re.match(r"^-\d+$", x): n = int(x[1:])
            elif x == "-f": continue
            else: files.append(x)
        data = self.c_cat(files) if files else (i or "")
        return "\n".join(data.splitlines()[-n:])

    def c_grep(self, a, i=None):
        flags = "".join(x[1:] for x in a if x.startswith("-"))
        rest = [x for x in a if not x.startswith("-")]
        if not rest:
            return "Usage: grep [-HhnlLoqvsriwFE] PATTERN [FILE]...", False
        pat, files = rest[0], rest[1:]
        data = self.c_cat(files) if files else (i or "")
        try:
            rx = re.compile(pat, re.I if "i" in flags else 0)
        except re.error:
            rx = re.compile(re.escape(pat))
        lines = [l for l in data.splitlines() if bool(rx.search(l)) != ("v" in flags)]
        if "c" in flags:
            return str(len(lines))
        return "\n".join(lines), bool(lines)
    c_egrep = c_grep

    def c_wc(self, a, i=None):
        data = i if i is not None else self.c_cat([x for x in a if not x.startswith("-")])
        if "-l" in a:
            return str(len(data.splitlines()))
        return f"{len(data.splitlines()):>7} {len(data.split()):>7} {len(data):>7}"

    def c_touch(self, a, i=None):
        for f in a:
            if not f.startswith("-") and not self._exists(self._abs(f)):
                self._write(f, "")
        return ""

    def c_mkdir(self, a, i=None):
        for d in a:
            if not d.startswith("-"):
                self.dirs.add(self._abs(d))
        return ""

    def c_rm(self, a, i=None):
        for f in a:
            if f.startswith("-"):
                continue
            p = self._abs(f)
            if p in self.files and not p.startswith(("/bin", "/sbin", "/usr")):
                self.files.pop(p, None)
            elif p in self.dirs and "-rf" in a and p not in ("/", "/tmp", "/root"):
                self.dirs.discard(p)
        return ""
    c_rmdir = c_rm

    def c_cp(self, a, i=None):
        a = [x for x in a if not x.startswith("-")]
        if len(a) >= 2 and self._exists(self._abs(a[0])):
            dst = self._abs(a[1])
            if dst in self.dirs:
                dst = posixpath.join(dst, posixpath.basename(a[0]))
            self.files[dst] = self._read(self._abs(a[0])) or ""
            return ""
        return f"cp: can't stat '{a[0] if a else ''}': No such file or directory", False

    def c_mv(self, a, i=None):
        r = self.c_cp(a)
        if r == "":
            self.files.pop(self._abs([x for x in a if not x.startswith('-')][0]), None)
        return r

    def c_chmod(self, a, i=None):
        self._execs = getattr(self, "_execs", set())
        for f in a[1:]:
            self._execs.add(self._abs(f))
        return ""
    def c_chown(self, a, i=None): return ""
    def c_ln(self, a, i=None): return ""
    def c_dd(self, a, i=None):
        return "0+1 records in\n0+1 records out"

    def c__exec(self, a, i=None):
        p = self._abs(a[0])
        if not self._exists(p):
            return f"-sh: {a[0]}: not found", False
        if p not in getattr(self, "_execs", set()) and not p.startswith(("/bin", "/sbin", "/usr")):
            return f"-sh: {a[0]}: Permission denied", False
        self._log("exec_attempt", payload=p, path=p, args=" ".join(a[1:])[:300])
        content = self._read(p) or ""
        if content.startswith("#!") or content.startswith("cd ") or "wget" in content:
            return ""
        return random.choice(["Illegal instruction", "Segmentation fault", ""])

    # network-ish commands --------------------------------------------------
    def c_wget(self, a, i=None):
        urls = [x for x in a if URL_RE.match(x) or re.match(r"^[\w.-]+\.\w+/", x) or HOST_RE.match(x.split("/")[0])]
        if not urls:
            return "BusyBox v1.31.1 multi-call binary.\n\nUsage: wget [-c|--continue] [-q|--quiet] [-O FILE] URL", False
        url = urls[0]
        out_name = None
        if "-O" in a:
            idx = a.index("-O")
            out_name = a[idx + 1] if idx + 1 < len(a) else None
        name = out_name or posixpath.basename(url.split("?")[0]) or "index.html"
        if name != "-":
            self.files[self._abs(name)] = f"#!/bin/sh\n# downloaded from {url}\n"
        host = re.sub(r"^\w+://", "", url).split("/")[0]
        if "-q" in a or "-qO-" in a:
            return ""
        return (f"Connecting to {host}\n{name}            100% |*******************************|   "
                f"{random.randint(900, 9000)}  0:00:00 ETA")

    def c_curl(self, a, i=None):
        urls = [x for x in a if URL_RE.match(x) or "." in x and not x.startswith("-")]
        if not urls:
            return "curl: try 'curl --help' for more information", False
        if "-o" in a or "-O" in a:
            name = a[a.index("-o") + 1] if "-o" in a and a.index("-o") + 1 < len(a) else \
                posixpath.basename(urls[0].split("?")[0])
            self.files[self._abs(name)] = f"#!/bin/sh\n# downloaded from {urls[0]}\n"
            return ""
        return ""

    def c_tftp(self, a, i=None):
        host = next((x for x in a if HOST_RE.match(x)), None)
        rfile = a[a.index("-r") + 1] if "-r" in a and a.index("-r") + 1 < len(a) else None
        if host and rfile:
            self._log("download_attempt", payload=f"tftp://{host}/{rfile}", url=f"tftp://{host}/{rfile}")
            self.files[self._abs(posixpath.basename(rfile))] = f"# tftp {host} {rfile}\n"
            return ""
        return "BusyBox v1.31.1 multi-call binary.\n\nUsage: tftp [OPTIONS] HOST [PORT]", False

    def c_ftpget(self, a, i=None):
        pos = [x for x in a if not x.startswith("-")]
        if len(pos) >= 3:
            url = f"ftp://{pos[0]}/{pos[2]}"
            self._log("download_attempt", payload=url, url=url)
            self.files[self._abs(pos[1])] = f"# ftp {url}\n"
            return ""
        return "Usage: ftpget [OPTIONS] HOST [LOCAL_FILE] REMOTE_FILE", False

    def c_ping(self, a, i=None):
        host = next((x for x in a if not x.startswith("-")), "localhost")
        return f"PING {host} ({host}): 56 data bytes\n--- {host} ping statistics ---\n4 packets transmitted, 0 packets received, 100% packet loss", False

    def c_ifconfig(self, a, i=None):
        p = self.p
        return (f"eth0      Link encap:Ethernet  HWaddr {p['mac']}\n"
                f"          inet addr:{p['ip']}  Bcast:{p['ip'].rsplit('.', 1)[0]}.255  Mask:255.255.255.0\n"
                "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n"
                "          RX packets:1834221 errors:0 dropped:0 overruns:0 frame:0\n"
                "          TX packets:922143 errors:0 dropped:0 overruns:0 carrier:0\n\n"
                "lo        Link encap:Local Loopback\n          inet addr:127.0.0.1  Mask:255.0.0.0\n"
                "          UP LOOPBACK RUNNING  MTU:65536  Metric:1")

    def c_ip(self, a, i=None):
        p = self.p
        return (f"1: lo: <LOOPBACK,UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n"
                f"2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n    link/ether {p['mac'].lower()}\n"
                f"    inet {p['ip']}/24 brd {p['ip'].rsplit('.', 1)[0]}.255 scope global eth0")

    def c_route(self, a, i=None):
        gw = self.p["ip"].rsplit(".", 1)[0] + ".1"
        return ("Kernel IP routing table\nDestination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
                f"0.0.0.0         {gw:<15} 0.0.0.0         UG    0      0        0 eth0")

    def c_netstat(self, a, i=None):
        ports = "22" if self.device == "smartlock" else "23"
        extra = "80  1883" if self.device == "smartlock" else "502  1883"
        lines = ["Active Internet connections (servers and established)",
                 "Proto Recv-Q Send-Q Local Address           Foreign Address         State"]
        for prt in [ports] + extra.split():
            lines.append(f"tcp        0      0 0.0.0.0:{prt:<17} 0.0.0.0:*               LISTEN")
        return "\n".join(lines)

    def c_ps(self, a, i=None):
        rows = ["  PID USER       VSZ STAT COMMAND"]
        for pid, user, cmd in self.p["procs"]:
            rows.append(f"{pid:>5} {user:<8} {random.randint(900, 4000):>5} S    {cmd}")
        rows.append(f"{random.randint(900, 999):>5} root      1100 R    ps")
        return "\n".join(rows)

    def c_top(self, a, i=None):
        return self.c_ps(a)

    def c_free(self, a, i=None):
        t = self.p["mem_kb"]
        return ("              total        used        free      shared  buff/cache   available\n"
                f"Mem:        {t:>7}     {t//2:>7}     {t//3:>7}        1024       {t//6:>5}     {t//2:>7}\n"
                "Swap:             0           0           0")

    def c_df(self, a, i=None):
        return ("Filesystem           1K-blocks      Used Available Use% Mounted on\n"
                "/dev/root                14336     14336         0 100% /\n"
                "tmpfs                    30860        64     30796   0% /tmp")

    def c_mount(self, a, i=None): return self._read("/proc/mounts")
    def c_dmesg(self, a, i=None): return f"[    0.000000] Booting Linux on physical CPU 0x0\n[    0.000000] Linux version {self.p['kernel']}"
    def c_lsmod(self, a, i=None): return "Module                  Size  Used by"
    def c_which(self, a, i=None):
        out = []
        for n in a:
            for d in ("/bin", "/sbin", "/usr/bin", "/usr/sbin"):
                if f"{d}/{n}" in self.files:
                    out.append(f"{d}/{n}"); break
        return "\n".join(out), bool(out)
    c_type = c_which

    def c_kill(self, a, i=None): return ""
    c_killall = c_kill
    c_pkill = c_kill
    c_nohup = lambda self, a, i=None: self._simple(" ".join(a))[0] if a else ""
    def c_sleep(self, a, i=None): return ""
    def c_crontab(self, a, i=None):
        if "-l" in a:
            return "no crontab for root", False
        return ""
    def c_passwd(self, a, i=None): return "passwd: password for root changed by root"
    def c_chpasswd(self, a, i=None): return ""
    def c_reboot(self, a, i=None): return "", True, True
    c_shutdown = c_reboot
    c_poweroff = c_reboot
    def c_iptables(self, a, i=None): return ""
    def c_service(self, a, i=None): return ""
    def c_vi(self, a, i=None): return ""
    c_nano = c_vi
    def c_md5sum(self, a, i=None):
        out = []
        for f in a:
            c = self._read(self._abs(f))
            if c is not None:
                out.append(f"{hashlib.md5(c.encode('latin-1','replace'), usedforsecurity=False).hexdigest()}  {f}")
        return "\n".join(out)
    def c_su(self, a, i=None): return ""
    c_sudo = lambda self, a, i=None: self._simple(" ".join(a))[0] if a else ""

    def c_busybox(self, a, i=None):
        return (f"{self.p['busybox']}\nBusyBox is copyrighted by many authors between 1998-2015.\n"
                "Licensed under GPLv2. See source distribution for detailed\ncopyright notices.\n\n"
                "Usage: busybox [function [arguments]...]\n\nCurrently defined functions:\n\t"
                + ", ".join(sorted(BIN_NAMES + SBIN_NAMES + USRBIN_NAMES)))

    # device specific -------------------------------------------------------
    def c_lockctl(self, a, i=None):
        if self.device != "smartlock":
            return self._not_found("lockctl"), False
        sub = a[0] if a else "status"
        if sub in ("lock", "unlock"):
            new = self.state.lock_action(sub, actor=f"ssh:{self.session.ip if self.session else 'local'}")
            self._log("state_change", payload=f"lock_state={new}", device_field="lock_state", value=new)
            return f"lockd: door {new}"
        s = self.state.get("smartlock")
        return (f"state: {s['lock_state']}\ndoor: {s['door']}\nbattery: {s['battery']}%\n"
                f"auto_lock: {s['auto_lock']}\nfirmware: {s['firmware']}")

    def c_sensorctl(self, a, i=None):
        if self.device != "sensor":
            return self._not_found("sensorctl"), False
        if a and a[0] == "set" and len(a) >= 3:
            changed = self.state.sensor_config(actor="telnet", **{a[1]: a[2]})
            if changed:
                self._log("state_change", payload=f"{a[1]}={a[2]}", device_field=a[1], value=a[2])
                return f"OK {a[1]}={a[2]}"
            return f"sensorctl: unknown key '{a[1]}'", False
        s = self.state.get("sensor")
        return "".join(f"{k:<20}{s.get(k)}\n" for k in
                       ("temperature", "pressure", "humidity", "alarm", "temp_threshold",
                        "pressure_threshold", "interval", "mode", "plc_link"))
