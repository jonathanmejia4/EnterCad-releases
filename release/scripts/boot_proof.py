#!/usr/bin/env python3
"""GATE-FREEZE-BOOT — every release self-proves it on the hosted runner.

This script is versioned in the SOURCE repo and *copied* into the public
releases repo alongside ``release.yml`` and ``build_manifest.py``; the
workflow runs it once, right after the frozen tree is signed and right
before it is zipped, so the artifact that ships is the exact tree this
script just proved. It never runs against source, never runs against an
installed wheel, and never touches Inventor/COM.

Stdlib only (release/workflows/release.yml's runner has no third-party
package installed for this step, and this file must be readable/runnable
even where ``cadmcp`` itself is not importable).

What it proves, worst-of-N (N = ``--samples``, R-9's BUD-1):

  * the frozen exe boots and answers the MCP stdio handshake
    (``initialize`` + ``notifications/initialized`` + ``tools/list``) with
    NO Python on ``PATH`` and NO ``PYTHON*``/``CADMCP_*`` environment
    inherited from the build, from a cwd that is never the source tree;
  * on the FIRST sample only (the rest just re-prove the boot, cheaply):
    the announced tool surface matches ``--baseline`` exactly, modulo
    owner-directed, ledger-listed drift in ``--additions`` — the same three
    rules ``tests/_surface.py`` enforces (removals forbidden, schema/
    description changes forbidden unless a listed additive-optional
    extension or description update, unlisted additions forbidden);
    ``serverInfo.version`` matches ``--expect-version`` when given; the
    handshake's ``instructions`` string starts with ``"preflight:"``
    (D3a/R-10);
  * EVERY sample then issues one ``tools/call`` for ``attach`` and requires
    the result to parse as a JSON envelope with
    ``reason == "application_not_running"`` — proving the call is refused
    at the preflight gate, before any COM contact, with no crash (there is
    no Inventor on the runner, ever);
  * EVERY sample closes stdin and requires a clean exit (code 0) within
    15 s, and every sample's spawn-to-``tools/list`` latency is < 10000 ms
    (R-9's BUD-1 hard ceiling) — all samples are recorded, not just the
    worst;
  * on Windows, the exe carries a Valid Authenticode signature (R-8) —
    unless BOTH ``--skip-signature`` is given AND the environment variable
    ``BOOT_PROOF_ALLOW_UNSIGNED=1`` is set (the release workflow never sets
    this; it exists for this script's own local/test use only). Passing
    ``--skip-signature`` WITHOUT that env var is refused outright, not
    silently downgraded to "run the check anyway".

No network beyond loopback: ``CADMCP_MANIFEST_URL`` is pointed at an
unreachable loopback address before the child ever starts, and the
preflight refusal this script proves on every sample fires before the
server would ever schedule its background manifest refresh in the first
place.

Exit code 0 iff every sample and every check above passed; non-zero (with
every failure named) otherwise. Always writes ``--out`` on completion,
whether it passed or failed, so a red run still leaves the report to read.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

PROTOCOL_VERSION = "2025-06-18"

# An address on the loopback range that nothing is listening on. The frozen
# server never fetches this (the preflight refusal fires first, on every
# sample), but pointing it at loopback rather than leaving the real
# manifest URL in place is belt-and-suspenders against D2's "zero
# non-loopback network on the startup path" (R-9).
LOOPBACK_MANIFEST_URL = "http://127.0.0.1:9/manifest.json"

BUD1_MS = 10000.0          # R-9: worst-of-N hard ceiling, per sample
EXIT_TIMEOUT_S = 15.0      # required clean-exit bound after stdin closes
READ_DEADLINE_S = 20.0     # per-message read bound (generous vs BUD1_MS: a
                           # slow sample must still be READABLE so its
                           # over-budget duration is recorded, not lost to
                           # a hung pipe read)

_TIMEOUT = object()  # sentinel distinct from None (EOF)


# ---------------------------------------------------------------------------
# tool-surface comparison — a self-contained port of tests/_surface.py's
# rules (this file must stay stdlib-only and importable with no `tests`
# package on the path, e.g. after R-4's sparse-checkout).
# ---------------------------------------------------------------------------

def load_baseline(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return {t["name"]: t for t in data["tools"]}


def load_additions_ledger(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    additions = {e["name"]: e for e in data.get("additions", [])}
    extensions = {e["name"]: e for e in data.get("extensions", [])}
    description_updates = {e["name"]: e for e in data.get("description_updates", [])}
    return additions, extensions, description_updates


def _diverged_field(baseline_tool, live_tool, field):
    in_b = field in baseline_tool
    in_l = field in live_tool
    if in_b != in_l:
        return True
    if not in_b:
        return False
    return json.dumps(baseline_tool[field], sort_keys=True) != json.dumps(
        live_tool[field], sort_keys=True
    )


def _additive_extension_ok(baseline_schema, live_schema, params_added):
    """True iff live_schema extends baseline_schema by adding ONLY the
    optional properties named in params_added. Mirrors
    tests/_surface.py::_additive_extension_ok exactly."""
    if not isinstance(baseline_schema, dict) or not isinstance(live_schema, dict):
        return False

    b_other = {k: v for k, v in baseline_schema.items() if k not in ("properties", "required")}
    l_other = {k: v for k, v in live_schema.items() if k not in ("properties", "required")}
    if json.dumps(b_other, sort_keys=True) != json.dumps(l_other, sort_keys=True):
        return False

    if set(baseline_schema.get("required", [])) != set(live_schema.get("required", [])):
        return False

    b_props = baseline_schema.get("properties", {}) or {}
    l_props = live_schema.get("properties", {}) or {}
    for key, schema in b_props.items():
        if key not in l_props:
            return False
        if json.dumps(schema, sort_keys=True) != json.dumps(l_props[key], sort_keys=True):
            return False

    new_props = set(l_props) - set(b_props)
    l_required = set(live_schema.get("required", []))
    if new_props & l_required:
        return False
    return new_props == set(params_added or [])


def compare_surface(baseline_by_name, additions, extensions, description_updates, live_tools):
    """-> (problems: list[str], report: dict). Same three (plus description)
    rules as tests/_surface.py::assert_surface: removals forbidden, a
    schema/description change forbidden unless the name is a listed
    extension/description-update whose difference is purely
    additive-optional, an addition forbidden unless listed in `additions`.
    """
    live_by_name = {t["name"]: t for t in live_tools}
    baseline_names = set(baseline_by_name)
    live_names = set(live_by_name)

    removed = sorted(baseline_names - live_names)
    changed = []
    changed_description = []
    extended = []
    description_updated = []

    for name in sorted(baseline_names & live_names):
        baseline_tool = baseline_by_name[name]
        live_tool = live_by_name[name]
        ext_entry = extensions.get(name)

        if _diverged_field(baseline_tool, live_tool, "description"):
            if name in description_updates or ext_entry is not None:
                description_updated.append(name)
            else:
                changed_description.append(name)

        schema_fields = ["inputSchema"]
        if "outputSchema" in baseline_tool:
            schema_fields.append("outputSchema")

        name_extended = False
        for field in schema_fields:
            if not _diverged_field(baseline_tool, live_tool, field):
                continue
            if ext_entry is not None and _additive_extension_ok(
                baseline_tool.get(field), live_tool.get(field), ext_entry.get("params_added")
            ):
                name_extended = True
            else:
                changed.append(f"{name}:{field}")
        if name_extended:
            extended.append(name)

    added = live_names - baseline_names
    added_unlisted = sorted(added - set(additions))
    added_listed = sorted(added & set(additions))

    report = {
        "removed": removed,
        "changed": changed,
        "changed_description": sorted(changed_description),
        "added_unlisted": added_unlisted,
        "added_listed": added_listed,
        "extended": sorted(extended),
        "description_updated": sorted(description_updated),
    }

    problems = []
    if removed:
        problems.append(f"removed tools (FORBIDDEN by INV-1): {removed}")
    if changed:
        problems.append(f"changed tool schemas (FORBIDDEN by INV-1): {changed}")
    if changed_description:
        problems.append(f"changed tool descriptions (FORBIDDEN by INV-1): {changed_description}")
    if added_unlisted:
        problems.append(f"unlisted tool additions (FORBIDDEN by INV-1): {added_unlisted}")

    return problems, report


# ---------------------------------------------------------------------------
# child process plumbing
# ---------------------------------------------------------------------------

def build_child_env(update_cache_path, manifest_url=LOOPBACK_MANIFEST_URL):
    """A copy of the current environment with every PATH entry containing
    "python" (case-insensitive) removed, every PYTHON*/CADMCP_* variable
    removed, and CADMCP_MANIFEST_URL/CADMCP_UPDATE_CACHE pointed at a
    controlled, loopback-only / runner-temp location."""
    env = dict(os.environ)

    path_key = next((k for k in env if k.upper() == "PATH"), None)
    if path_key is not None:
        entries = env[path_key].split(os.pathsep)
        env[path_key] = os.pathsep.join(e for e in entries if "python" not in e.lower())

    for key in list(env):
        upper = key.upper()
        if upper.startswith("PYTHON") or upper.startswith("CADMCP_"):
            del env[key]

    env["CADMCP_MANIFEST_URL"] = manifest_url
    env["CADMCP_UPDATE_CACHE"] = update_cache_path
    return env


class _LineReader:
    """Background-thread line reader so a read can be bounded by a deadline
    without blocking forever on a hung child — needed on Windows, where
    pipe reads have no built-in timeout."""

    def __init__(self, stream):
        self._q: "queue.Queue" = queue.Queue()
        self._t = threading.Thread(target=self._pump, args=(stream,), daemon=True)
        self._t.start()

    def _pump(self, stream):
        try:
            for line in iter(stream.readline, b""):
                self._q.put(line)
        except (OSError, ValueError):
            pass
        finally:
            self._q.put(None)  # EOF sentinel

    def readline(self, timeout):
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return _TIMEOUT

    def drain_text(self):
        chunks = []
        while True:
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                break
            if item is None:
                break
            chunks.append(item)
        return b"".join(chunks).decode(errors="replace")


class _ChildRPC:
    """One spawned [exe, "serve"] child, speaking newline-delimited JSON-RPC
    over stdio. Raises RuntimeError (with a clear reason) on any protocol
    failure -- caller catches it per-sample."""

    def __init__(self, cmd, cwd, env):
        self.proc = subprocess.Popen(
            cmd, cwd=cwd, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self._out = _LineReader(self.proc.stdout)
        self._err = _LineReader(self.proc.stderr)

    def _write(self, msg):
        try:
            self.proc.stdin.write((json.dumps(msg) + "\n").encode())
            self.proc.stdin.flush()
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"write to child stdin failed: {exc}") from exc

    def send(self, msg_id, method, params=None):
        self._write({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}})

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._write(msg)

    def recv(self, deadline=READ_DEADLINE_S):
        line = self._out.readline(deadline)
        if line is _TIMEOUT:
            raise RuntimeError(f"no response from child within {deadline:.0f}s")
        if not line:
            stderr_tail = self._err.drain_text()[-2000:]
            raise RuntimeError(f"child closed stdout unexpectedly; stderr: {stderr_tail!r}")
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"child emitted non-JSON line: {line!r} ({exc})") from exc
        if "error" in msg and msg.get("error") is not None:
            raise RuntimeError(f"child returned a JSON-RPC error: {msg['error']!r}")
        return msg.get("result")

    def close_and_wait(self, timeout=EXIT_TIMEOUT_S):
        try:
            self.proc.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            code = self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=timeout)
            stderr_tail = self._err.drain_text()[-2000:]
            raise RuntimeError(
                f"child did not exit within {timeout:.0f}s of stdin closing "
                f"(killed); stderr: {stderr_tail!r}"
            )
        if code != 0:
            stderr_tail = self._err.drain_text()[-2000:]
            raise RuntimeError(f"child exited {code}, expected 0; stderr: {stderr_tail!r}")
        return code


def run_one_sample(cmd, cwd, env, *, index, expect_version, baseline_by_name,
                    additions, extensions, description_updates, full_check):
    """Runs the boot handshake once. Returns (sample_report: dict,
    problems: list[str]). Never raises -- every failure is folded into
    `problems` and the sample report so one bad sample never aborts the
    other N-1."""
    problems = []
    sample = {"index": index, "duration_ms": None, "exit_code": None,
              "attach_reason": None, "surface": None}

    t0 = time.perf_counter()
    try:
        child = _ChildRPC(cmd, cwd, env)
    except OSError as exc:
        problems.append(f"sample {index}: failed to spawn child: {exc}")
        return sample, problems

    try:
        child.send(1, "initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "boot-proof", "version": "0"},
        })
        init_result = child.recv()
        child.notify("notifications/initialized")
        child.send(2, "tools/list", {})
        list_result = child.recv()
        duration_ms = (time.perf_counter() - t0) * 1000.0
        sample["duration_ms"] = duration_ms

        if full_check:
            server_info = (init_result or {}).get("serverInfo") or {}
            if expect_version is not None and server_info.get("version") != expect_version:
                problems.append(
                    f"sample {index}: serverInfo.version {server_info.get('version')!r} "
                    f"!= --expect-version {expect_version!r}"
                )
            instructions = (init_result or {}).get("instructions")
            if not isinstance(instructions, str) or not instructions.startswith("preflight:"):
                problems.append(
                    f"sample {index}: instructions must be a str starting 'preflight:', "
                    f"got {instructions!r}"
                )
            live_tools = (list_result or {}).get("tools")
            if not isinstance(live_tools, list):
                problems.append(f"sample {index}: tools/list returned no tool list: {list_result!r}")
            else:
                surface_problems, surface_report = compare_surface(
                    baseline_by_name, additions, extensions, description_updates, live_tools
                )
                sample["surface"] = surface_report
                problems.extend(f"sample {index}: {p}" for p in surface_problems)

        child.send(3, "tools/call", {"name": "attach", "arguments": {}})
        call_result = child.recv() or {}
        try:
            text = call_result["content"][0]["text"]
            envelope = json.loads(text)
            reason = envelope.get("reason")
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            problems.append(
                f"sample {index}: tools/call attach did not return a parseable "
                f"envelope ({exc}): {call_result!r}"
            )
            reason = None
        sample["attach_reason"] = reason
        if reason != "application_not_running":
            problems.append(
                f"sample {index}: tools/call attach returned reason={reason!r}, "
                "expected 'application_not_running' (no Inventor on the runner — "
                "the call must be refused before any COM contact)"
            )

        exit_code = child.close_and_wait()
        sample["exit_code"] = exit_code

    except RuntimeError as exc:
        problems.append(f"sample {index}: {exc}")
        try:
            child.proc.kill()
            child.proc.wait(timeout=5)
        except Exception:
            pass

    if sample["duration_ms"] is not None and sample["duration_ms"] >= BUD1_MS:
        problems.append(
            f"sample {index}: spawn-to-tools/list took {sample['duration_ms']:.0f}ms "
            f">= BUD-1's {BUD1_MS:.0f}ms ceiling"
        )

    return sample, problems


# ---------------------------------------------------------------------------
# signature verification
# ---------------------------------------------------------------------------

def verify_signature(exe_path):
    """Authenticode via PowerShell Get-AuthenticodeSignature. -> dict with
    at least "checked" and, when checked, "status" (Valid/NotSigned/...)."""
    if not sys.platform.startswith("win"):
        return {"checked": False, "reason": "not running on Windows"}

    escaped = str(exe_path).replace("'", "''")
    ps_command = f"(Get-AuthenticodeSignature -LiteralPath '{escaped}').Status.ToString()"
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"checked": True, "status": None, "error": f"powershell invocation failed: {exc}"}

    status = (proc.stdout or "").strip()
    result = {"checked": True, "status": status}
    if proc.returncode != 0 or not status:
        result["error"] = (proc.stderr or "").strip() or f"powershell exited {proc.returncode}"
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="boot_proof.py",
        description="GATE-FREEZE-BOOT: prove the frozen exe boots and speaks MCP "
                    "with no Python on PATH, worst-of-N.",
    )
    parser.add_argument(
        "--exe", required=True, nargs="+", metavar="PATH",
        help="the frozen exe to boot, as an argv prefix (normally one token, e.g. "
             "dist/entercad/entercad.exe; a test may pass an absolute interpreter "
             "path plus a fake-server script instead — \"serve\" is appended by "
             "this script either way)",
    )
    parser.add_argument("--baseline", required=True, help="path to tools-baseline.json")
    parser.add_argument("--additions", required=True, help="path to tools-additions.json")
    parser.add_argument("--samples", type=int, default=9, help="worst-of-N sample count")
    parser.add_argument("--expect-version", default=None,
                        help="serverInfo.version must equal this, when given")
    parser.add_argument("--out", required=True, help="where to write the JSON report")
    parser.add_argument(
        "--skip-signature", action="store_true",
        help="skip the Authenticode check -- ONLY takes effect together with "
             "env BOOT_PROOF_ALLOW_UNSIGNED=1; passing this flag without that "
             "env var is refused, not silently downgraded",
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.skip_signature and os.environ.get("BOOT_PROOF_ALLOW_UNSIGNED") != "1":
        print(
            "::error::BOOT PROOF REFUSED: --skip-signature was given without "
            "env BOOT_PROOF_ALLOW_UNSIGNED=1 set — the release workflow never sets "
            "this combination; refusing to silently skip the Authenticode check",
            file=sys.stderr,
        )
        return 1

    try:
        baseline_by_name = load_baseline(args.baseline)
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"::error::BOOT PROOF FAILED: unreadable --baseline: {exc}", file=sys.stderr)
        return 1

    try:
        additions, extensions, description_updates = load_additions_ledger(args.additions)
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"::error::BOOT PROOF FAILED: unreadable --additions: {exc}", file=sys.stderr)
        return 1

    exe = [os.path.abspath(tok) for tok in args.exe]
    cmd = exe + ["serve"]

    runner_temp = os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()
    run_root = tempfile.mkdtemp(prefix="boot_proof_", dir=runner_temp)
    update_cache_path = os.path.join(run_root, "update-cache.json")
    env = build_child_env(update_cache_path)

    problems = []
    samples = []
    for i in range(args.samples):
        sample, sample_problems = run_one_sample(
            cmd, run_root, env,
            index=i, expect_version=args.expect_version,
            baseline_by_name=baseline_by_name, additions=additions,
            extensions=extensions, description_updates=description_updates,
            full_check=(i == 0),
        )
        samples.append(sample)
        problems.extend(sample_problems)

    skip_signature = args.skip_signature and os.environ.get("BOOT_PROOF_ALLOW_UNSIGNED") == "1"
    if skip_signature:
        signature = {"checked": False, "reason": "--skip-signature + BOOT_PROOF_ALLOW_UNSIGNED=1"}
    else:
        signature = verify_signature(exe[0])
        if signature.get("checked") and signature.get("status") != "Valid":
            problems.append(
                f"Authenticode signature not Valid for {exe[0]}: {signature}"
            )

    durations = [s["duration_ms"] for s in samples if s["duration_ms"] is not None]
    worst_ms = max(durations) if durations else None

    passed = not problems
    report = {
        "exe": exe,
        "expect_version": args.expect_version,
        "samples": samples,
        "worst_ms": worst_ms,
        "signature": signature,
        "problems": problems,
        "passed": passed,
    }

    out_path = Path(args.out)
    if out_path.parent != Path(""):
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")

    worst_str = f"{worst_ms:.0f}ms" if worst_ms is not None else "n/a"
    sig_str = signature.get("status") if signature.get("checked") else "skipped"
    if passed:
        print(
            f"BOOT PROOF: PASS samples={len(samples)} worst={worst_str} "
            f"signature={sig_str} report={out_path}"
        )
        return 0

    print(
        f"::error::BOOT PROOF: FAIL samples={len(samples)} worst={worst_str} "
        f"signature={sig_str} report={out_path} problems={problems}"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
