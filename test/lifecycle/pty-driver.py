"""Runs one command under a pseudo-terminal, detached from the caller's process tree, feeding it scripted lines.

Why: `uninstall`, `approver init` and `mcp wrap-config` run only for "a person at the keyboard": a real terminal, and
not a descendant of a Claude Code session. A test has neither, so this stands in for the person's own terminal window:
it double-forks (the command's parent becomes init, as a terminal emulator's shell is) and gives the command a pty.
argv: result_file, then a JSON document {"argv": [...], "env": {...}, "cwd": "...", "inputs": [[expect_regex, line], ...]}.
Writes {"code", "output"} as JSON to result_file when done.
"""
import json, os, pty, re, select, sys, time

result_file = sys.argv[1]
spec = json.loads(sys.argv[2])

if os.fork() != 0:
    os._exit(0)
os.setsid()
if os.fork() != 0:
    os._exit(0)

pid, fd = pty.fork()
if pid == 0:
    os.chdir(spec["cwd"])
    os.execve(spec["argv"][0], spec["argv"], spec["env"])
inputs = list(spec.get("inputs", []))
out = b""
consumed = 0
deadline = time.time() + spec.get("timeout", 60)
code = None
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            chunk = b""
        if chunk == b"":
            break
        out += chunk
        m = re.search(inputs[0][0], out[consumed:].decode("utf8", "replace")) if inputs else None
        if m:
            consumed = len(out)
            os.write(fd, (inputs[0][1] + "\r").encode())
            inputs.pop(0)
try:
    if time.time() >= deadline:
        os.kill(pid, 9)
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
except Exception:
    code = -1
tmp = result_file + ".tmp"
with open(tmp, "w") as f:
    json.dump({"code": code, "output": out.decode("utf8", "replace")}, f)
os.rename(tmp, result_file)
