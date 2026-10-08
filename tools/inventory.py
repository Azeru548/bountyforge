#!/usr/bin/env python3
"""
BountyForge tool inventory - reports which engines are runnable vs blocked.

Scans every sibling tool and classifies it:
  RUNNABLE  - executes --help (or its own entrypoint) successfully
  BLOCKED   - a required module, env var, or CLI dependency is missing
  DSL       - not a standalone script; needs an external runtime (e.g. glider)
  BROKEN    - crashes for a reason unrelated to the environment

Usage:
  python tools/inventory.py
  python tools/inventory.py --json
  python tools/inventory.py --verbose
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent

# Third-party runtimes these scripts are written for, not pip-installable apps.
DSL_RUNTIMES = {
    "glider": "crytic `glider` (run as: glider run <file>.py) - not on PyPI",
}

# External CLIs the hunting skills expect on PATH.
EXTERNAL_CLIS = [
    "curl", "nmap", "ffuf", "gobuster", "feroxbuster", "wfuzz",
    "sqlmap", "amass", "subfinder", "httpx", "nuclei", "nikto", "katana",
    "dalfox", "zaproxy", "burpsuite",
]

STATUS_ORDER = {"RUNNABLE": 0, "BLOCKED": 1, "DSL": 2, "BROKEN": 3}


def classify_imports(path: Path):
    """Return (missing_local, third_party) module names referenced by path.

    Uses a line scan rather than a nested quantifier regex -- the earlier
    `try:\\s*\\n((?:\\s+.+\\n)+?)except` pattern backtracked catastrophically
    on multi-KB files and hung the inventory.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    missing, third = set(), set()
    guarded = set()
    # Stack of try-block indentation levels currently open.
    try_stack = []

    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        # Close any try blocks whose body has de-indented past them.
        while try_stack and indent <= try_stack[-1]:
            try_stack.pop()

        if stripped.startswith("try:"):
            try_stack.append(indent)
            continue

        m = re.match(r"(?:from|import)\s+tools\.(\w+)", stripped)
        if m:
            target = guarded if try_stack else missing
            target.add(m.group(1))
            continue

        m = re.match(r"(?:from|import)\s+([a-zA-Z_]\w*)", stripped)
        if m and not try_stack:
            mod = m.group(1)
            if mod != "tools" and mod not in sys.stdlib_module_names:
                third.add(mod)

    # Only report local modules that are actually absent from this directory.
    missing_local = {
        n for n in missing | guarded
        if not (TOOLS / f"{n}.py").exists()
    }
    # Hard-fail set: referenced outside any try/except AND absent.
    hard_missing = {
        n for n in missing
        if not (TOOLS / f"{n}.py").exists()
    }
    return sorted(hard_missing), sorted(third), sorted(missing_local - hard_missing)


def looks_like_dsl(path: Path) -> str:
    """Detect scripts meant for an external DSL runtime, not `python file.py`."""
    text = path.read_text(encoding="utf-8", errors="replace")[:2000]
    for line in text.splitlines():
        if line.startswith("Usage:") and "glider run" in line:
            return "glider"
        if line.startswith("glider run"):
            return "glider"
    if re.search(r"^from glider import", text, re.M):
        return "glider"
    return ""


def run_entrypoint(path: Path, verbose: bool = False):
    """Try the tool's own help/entrypoint. Returns (exit_code, first_output_line)."""
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"          # Windows console defaults to cp1252
    env.setdefault("BF_STATE_DIR", str(REPO / "state"))

    # Only probe --help when the file parses args; a bare run on a
    # non-argparse script executes its real logic (network calls, input()).
    text = path.read_text(encoding="utf-8", errors="replace")
    has_argparse = "argparse" in text and "parse_args" in text
    candidates = [["--help"]] if has_argparse else []
    last_code, last_line = None, ""

    for args in candidates:
        try:
            proc = subprocess.run(
                [sys.executable, str(path), *args],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", env=env, cwd=str(TOOLS), timeout=25,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            return 124, "timed out after 25s"
        except OSError as exc:
            return 126, f"spawn failed: {exc}"

        out = (proc.stdout or "") + (proc.stderr or "")
        first = next((l.strip() for l in out.splitlines() if l.strip()), "")
        last_code, last_line = proc.returncode, first

        # argparse usage => help worked
        if "usage:" in out.lower():
            return 0, first
        # No-arg tools that print help without flags also count.
        if proc.returncode == 0 and out.strip():
            return 0, first
        if verbose and args:
            print(f"      tried {' '.join(args) or '<no args>'} -> {proc.returncode}: {first[:90]}")

    if not candidates:
        # No argparse: don't execute. Compile + resolve imports statically.
        try:
            compile(text, str(path), "exec")
        except SyntaxError as exc:
            return 2, f"syntax error line {exc.lineno}: {exc.msg}"
        return 0, "no argparse - not executed (verified compiles)"

    return last_code if last_code is not None else 1, last_line


def inspect_tool(path: Path, verbose: bool = False) -> dict:
    record = {
        "file": path.name,
        "status": "RUNNABLE",
        "reason": "",
        "missing_local": [],
        "optional_missing": [],
        "third_party": [],
        "cli": [],
        "detail": "",
    }

    if path.suffix == ".sh":
        record["status"] = "BLOCKED"
        record["reason"] = "bash script - run under WSL/Git Bash, not cmd"
        bash = shutil.which("bash")
        if not bash:
            record["reason"] = "bash not on PATH"
            return record

        # WSL's bash cannot open C:\... paths. Try the Windows path first
        # (Git Bash accepts it); if that fails, retry via a /mnt/<drive>/ form.
        # Note: `wslpath` lives inside WSL, so it is not callable from here.
        attempts = [str(path)]
        m = re.match(r"([A-Za-z]):[\\/](.*)", str(path))
        if m:
            rel = m.group(2).replace("\\", "/")
            attempts.append(f"/mnt/{m.group(1).lower()}/{rel}")

        last_err = ""
        for check_path in attempts:
            try:
                proc = subprocess.run(
                    [bash, "-n", check_path], capture_output=True,
                    text=True, encoding="utf-8", errors="replace", timeout=60,
                )
            except (OSError, subprocess.TimeoutExpired):
                # WSL cold-start can exceed 20s; report as unverified.
                record["reason"] += " (bash -n timed out - syntax unverified)"
                return record

            # WSL prints its own diagnostics (systemd session warnings) to
            # stderr; only bash's own "syntax error" lines are meaningful.
            syntax_lines = [
                l.strip() for l in (proc.stderr or "").splitlines()
                if "syntax error" in l
            ]
            if syntax_lines:
                record["status"] = "BROKEN"
                record["reason"] = f"bash syntax error: {syntax_lines[0][:110]}"
                return record
            if proc.returncode == 0:
                return record
            last_err = (proc.stderr or "").strip().splitlines()
            last_err = last_err[0] if last_err else f"exit {proc.returncode}"

        record["reason"] = f"bash unavailable for this script ({last_err[:70]})"
        return record

    runtime = looks_like_dsl(path)
    if runtime:
        record["status"] = "DSL"
        record["reason"] = DSL_RUNTIMES.get(runtime, runtime)
        return record

    missing_local, third_party, optional_missing = classify_imports(path)
    record["missing_local"] = missing_local
    record["optional_missing"] = optional_missing
    record["third_party"] = third_party

    if missing_local:
        record["status"] = "BLOCKED"
        record["reason"] = f"missing module(s): {', '.join(missing_local)}"
        return record

    code, detail = run_entrypoint(path, verbose=verbose)
    record["detail"] = detail

    if code == 0:
        record["status"] = "RUNNABLE"
        return record

    # Attribute/module errors point at missing third-party deps.
    m = re.search(r"ModuleNotFoundError: No module named '([^']+)'", detail)
    if m:
        record["status"] = "BLOCKED"
        record["reason"] = f"missing package: {m.group(1)}"
        return record
    m = re.search(r"ModuleNotFoundError: No module named 'tools\.(\w+)'", detail)
    if m:
        record["status"] = "BLOCKED"
        record["reason"] = f"missing module: tools.{m.group(1)}"
        return record

    if "http_pool.py required" in detail:
        record["status"] = "BLOCKED"
        record["reason"] = "needs tools/http_pool.py (not shipped in repo)"
        return record

    if code == 124:
        record["status"] = "BROKEN"
        record["reason"] = "help probe did not return within 25s (hang?)"
        return record

    record["status"] = "BROKEN"
    record["reason"] = detail[:160] or f"exit {code} with no output"
    return record


def check_external_clis() -> list:
    found = []
    for cli in EXTERNAL_CLIS:
        path = shutil.which(cli)
        if path:
            found.append({"cli": cli, "path": path})
    return found


def check_env() -> dict:
    state = os.environ.get("BF_STATE_DIR") or str(REPO / "state")
    return {
        "python": sys.version.split()[0],
        "console_encoding": getattr(sys.stdout, "encoding", "?"),
        "utf8_mode": bool(os.environ.get("PYTHONUTF8")),
        "BF_STATE_DIR": state,
        "BF_STATE_DIR_exists": Path(state).exists(),
    }


def main():
    parser = argparse.ArgumentParser(description="BountyForge tool inventory")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--verbose", action="store_true", help="show each probe attempt")
    args = parser.parse_args()

    tools = sorted(
        p for p in TOOLS.iterdir()
        if p.is_file() and p.suffix in {".py", ".sh"} and p.name != Path(__file__).name
    )
    records = [inspect_tool(p, verbose=args.verbose) for p in tools]
    records.sort(key=lambda r: (STATUS_ORDER[r["status"]], r["file"]))

    report = {
        "env": check_env(),
        "tools": records,
        "summary": {
            s: sum(1 for r in records if r["status"] == s)
            for s in ("RUNNABLE", "BLOCKED", "DSL", "BROKEN")
        },
        "external_clis": check_external_clis(),
    }

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    env = report["env"]
    print("=" * 72)
    print("  BOUNTYFORGE - TOOL INVENTORY")
    print("=" * 72)
    print(f"  python {env['python']}   console={env['console_encoding']}   "
          f"utf8_mode={env['utf8_mode']}")
    print(f"  BF_STATE_DIR={env['BF_STATE_DIR']}  exists={env['BF_STATE_DIR_exists']}")
    print()

    icons = {"RUNNABLE": "[ OK ]", "BLOCKED": "[BLK ]", "DSL": "[DSL ]", "BROKEN": "[FAIL]"}
    for status in ("RUNNABLE", "BLOCKED", "DSL", "BROKEN"):
        group = [r for r in records if r["status"] == status]
        if not group:
            continue
        print(f"  {icons[status]} {status} ({len(group)})")
        for r in group:
            note = r["reason"] or r["detail"][:70]
            print(f"        {r['file']:<30} {note}")
        print()

    s = report["summary"]
    print(f"  TOTAL {len(records)}: "
          f"{s['RUNNABLE']} runnable, {s['BLOCKED']} blocked, "
          f"{s['DSL']} dsl, {s['BROKEN']} broken")
    print()

    missing = [c for c in EXTERNAL_CLIS if not shutil.which(c)]
    print(f"  EXTERNAL CLIS: {len(EXTERNAL_CLIS) - len(missing)}/{len(EXTERNAL_CLIS)} on PATH")
    if missing:
        print(f"        missing: {', '.join(missing)}")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
