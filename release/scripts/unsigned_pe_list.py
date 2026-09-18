#!/usr/bin/env python3
"""F11b — sign ONLY the PE files that do not already carry a valid signature.

This script is versioned in the SOURCE repo and *copied* into the public
releases repo alongside ``release.yml``, ``boot_proof.py`` and
``build_manifest.py``. The release workflow runs it twice, around the Azure
Trusted Signing step:

``plan``   (before signing) walks the frozen one-dir tree, asks Windows about
           the Authenticode signature of every PE file (``.exe``/``.dll``/
           ``.pyd``, the filter the signing step used to sweep with) and splits
           them:

             * KEPT    -- carries a valid EMBEDDED Authenticode signature
                          (python312.dll from the PSF, VCRUNTIME140.dll from
                          Microsoft, ...). These are left byte-for-byte as they
                          are: re-signing them replaces their publisher's
                          signature with ours, which is what v0.1.0's
                          whole-folder sweep did to 45 Microsoft-signed
                          C-runtime files.
             * TO SIGN -- everything else: no signature, a broken one
                          (bad digest, untrusted root, expired without a
                          timestamp), or validity that exists only as an entry
                          in the build machine's Windows catalog database --
                          that does not travel with the file to a user's
                          machine. entercad.exe is always here: it is built on
                          the runner.

           It writes the TO SIGN list as the signing action's ``files-catalog``
           (paths relative to the catalog's own folder, one per line, no blank
           lines -- the format the pinned action's TrustedSigning module reads
           with Join-Path + Resolve-Path) and a JSON plan that records each
           KEPT file's embedded signer thumbprint.

``verify`` (after signing) re-reads every PE in the tree and fails unless the
           set of PE files is exactly the planned set; every one is Valid AND
           carries a valid embedded signature; every KEPT file still carries
           the SAME embedded signer it had before signing; and every TO SIGN
           file is now signed by ``--expect-cn``. That is the Smart App Control
           invariant: every PE ends up with either its original valid
           signature or ours, and never ours in place of someone else's.

WHY NOT Get-AuthenticodeSignature ALONE. It consults the machine's catalog
database FIRST and, on a catalog hit, reports that signature instead of the
file's own: on a machine with the VC++ runtime installed, VCRUNTIME140.dll
reads ``Valid/Catalog`` although it carries Microsoft's embedded signature.
Classifying on that answer would re-sign it -- the very defect this script
exists to remove -- and trusting a catalog hit would keep a file whose
validity the user's machine may not share. So the KEEP/SIGN decision is made by
``WinVerifyTrust`` with ``WTD_CHOICE_FILE`` (the embedded signature only, never
a catalog), and the embedded signer is read with
``X509Certificate.CreateFromSignedFile``. ``Get-AuthenticodeSignature``'s
Status is still recorded and must read Valid for every file after signing.

Stdlib only; one PowerShell session per invocation. Windows only: there is no
other way to ask the question this script asks, so on any other platform it
fails closed.

Exit codes: 0 on success; 1 on any violation or unreadable input (every
violation is named, as a GitHub ``::error::`` line).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

PE_SUFFIXES = (".exe", ".dll", ".pyd")

# The pinned signing action resolves every catalog line with Resolve-Path,
# which treats these characters as wildcards. A name carrying one could match
# a different file, several, or none -- so it is refused, never escaped.
WILDCARD_CHARS = frozenset("[]*?")

PLAN_SCHEMA = 1

# One PowerShell session reads every path listed (UTF-8, one per line) in
# __LIST__ and writes a JSON array to __OUT__. -EncodedCommand is used rather
# than -File so the machine's script execution policy never matters.
#
# EmbeddedAuthenticode.Verify is WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)
# over WTD_CHOICE_FILE -- the file's EMBEDDED signature only; a catalog is never
# consulted -- with no UI and no revocation lookup. 0 = valid.
_PS_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class EmbeddedAuthenticode {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    public static int Verify(string path) {
        Guid action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        WINTRUST_FILE_INFO file = new WINTRUST_FILE_INFO();
        file.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
        file.pcwszFilePath = path;
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
        try {
            Marshal.StructureToPtr(file, pFile, false);
            WINTRUST_DATA data = new WINTRUST_DATA();
            data.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
            data.dwUIChoice = 2;           // WTD_UI_NONE
            data.fdwRevocationChecks = 0;  // WTD_REVOKE_NONE
            data.dwUnionChoice = 1;        // WTD_CHOICE_FILE
            data.pFile = pFile;
            data.dwStateAction = 1;        // WTD_STATEACTION_VERIFY
            data.dwProvFlags = 0x10;       // WTD_REVOCATION_CHECK_NONE
            int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.dwStateAction = 2;        // WTD_STATEACTION_CLOSE
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            return result;
        } finally {
            Marshal.DestroyStructure(pFile, typeof(WINTRUST_FILE_INFO));
            Marshal.FreeHGlobal(pFile);
        }
    }
}
'@
$paths = [System.IO.File]::ReadAllLines('__LIST__', [System.Text.Encoding]::UTF8)
$rows = foreach ($p in $paths) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    $s = Get-AuthenticodeSignature -LiteralPath $p
    $embedded = $null
    try {
        $embedded = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (
            [System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($p))
    } catch {
        $embedded = $null
    }
    [ordered]@{
        path                = $p
        status              = [string]$s.Status
        type                = [string]$s.SignatureType
        subject             = $(if ($s.SignerCertificate) { [string]$s.SignerCertificate.Subject } else { '' })
        embedded_hr         = [int][EmbeddedAuthenticode]::Verify($p)
        embedded_subject    = $(if ($embedded) { [string]$embedded.Subject } else { '' })
        embedded_thumbprint = $(if ($embedded) { [string]$embedded.Thumbprint } else { '' })
    }
}
$json = ConvertTo-Json -InputObject @($rows) -Depth 3
[System.IO.File]::WriteAllText('__OUT__', $json, (New-Object System.Text.UTF8Encoding $false))
"""


class SignPlanError(Exception):
    """A named reason this tree cannot be planned or verified."""


# ---------------------------------------------------------------------------
# reading the tree and its signatures
# ---------------------------------------------------------------------------

def pe_files(tree):
    """Every PE file under ``tree`` (by extension, case-insensitive), sorted."""
    return sorted(
        p for p in Path(tree).rglob("*")
        if p.is_file() and p.suffix.lower() in PE_SUFFIXES
    )


def rel(tree, path):
    return Path(path).relative_to(tree).as_posix()


def _powershell():
    root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT") or os.environ.get("windir")
    if root:
        exe = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        if os.path.isfile(exe):
            return exe
    return "powershell"


def _ps_literal(text):
    return str(text).replace("'", "''")


def read_signatures(paths):
    """-> {path: row} for every path in ``paths``, where row carries
    ``status``/``type``/``subject`` (Get-AuthenticodeSignature's catalog-first
    view) and ``embedded_hr``/``embedded_subject``/``embedded_thumbprint`` (the
    file's own embedded signature: WinVerifyTrust result, 0 = valid)."""
    if not sys.platform.startswith("win"):
        raise SignPlanError(
            "Authenticode can only be read on Windows; refusing to guess a signing set"
        )
    paths = [str(p) for p in paths]
    if not paths:
        return {}
    with tempfile.TemporaryDirectory(prefix="pe-sig-") as tmp:
        list_path = os.path.join(tmp, "paths.txt")
        out_path = os.path.join(tmp, "signatures.json")
        Path(list_path).write_text("\n".join(paths) + "\n", encoding="utf-8")
        script = (_PS_TEMPLATE
                  .replace("__LIST__", _ps_literal(list_path))
                  .replace("__OUT__", _ps_literal(out_path)))
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        try:
            proc = subprocess.run(
                [_powershell(), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                capture_output=True, text=True, timeout=900,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SignPlanError(f"powershell invocation failed: {exc!r}") from exc
        if proc.returncode != 0 or not os.path.isfile(out_path):
            detail = (proc.stderr or proc.stdout or "").strip()[-2000:]
            raise SignPlanError(
                f"reading Authenticode signatures failed (exit {proc.returncode}): {detail}"
            )
        rows = json.loads(Path(out_path).read_text(encoding="utf-8-sig"))
    if isinstance(rows, dict):  # defensive: a lone object instead of a 1-array
        rows = [rows]
    by_path = {row["path"]: row for row in rows}
    missing = [p for p in paths if p not in by_path]
    if missing:
        raise SignPlanError(f"no Authenticode answer for {len(missing)} file(s): {missing[:5]}")
    return {p: by_path[p] for p in paths}


def embedded_valid(row):
    """True iff the file's OWN embedded Authenticode signature verifies."""
    return row.get("embedded_hr") == 0


def hr_text(row):
    code = row.get("embedded_hr")
    if code == 0:
        return "Valid"
    if isinstance(code, int):
        return f"0x{code & 0xFFFFFFFF:08X}"
    return repr(code)


def subject_cn(subject):
    """The CN of an X.500 subject string, or None."""
    for part in re.split(r",\s*(?=[A-Za-z][A-Za-z0-9.]*=)", subject or ""):
        key, sep, value = part.partition("=")
        if sep and key.strip().upper() == "CN":
            return value.strip().strip('"')
    return None


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------

def plan(tree, catalog, out):
    tree = Path(tree).resolve()
    catalog = Path(catalog).resolve()
    out = Path(out).resolve()
    if not tree.is_dir():
        raise SignPlanError(f"frozen tree not found: {tree}")
    for label, path in (("catalog", catalog), ("plan", out)):
        if path == tree or tree in path.parents:
            raise SignPlanError(
                f"the {label} file {path} is inside the frozen tree {tree}; "
                "it would ship in the artifact"
            )

    files = pe_files(tree)
    if not files:
        raise SignPlanError(f"no PE files ({', '.join(PE_SUFFIXES)}) under {tree}")
    signatures = read_signatures(files)

    to_sign, kept = [], []
    for path in files:
        row = signatures[str(path)]
        entry = {"path": rel(tree, path), "status": row["status"], "type": row["type"],
                 "embedded": hr_text(row)}
        if embedded_valid(row):
            entry.update(subject=row["embedded_subject"], thumbprint=row["embedded_thumbprint"])
            kept.append(entry)
        else:
            to_sign.append(entry)

    if not to_sign:
        raise SignPlanError(
            "nothing to sign: every PE already carries a valid signature, but the "
            "frozen exe is built on the runner and must always be signed here"
        )

    lines = []
    for entry in to_sign:
        bad = sorted(set(entry["path"]) & WILDCARD_CHARS)
        if bad:
            raise SignPlanError(
                f"{entry['path']!r} contains wildcard character(s) {bad} that the signing "
                "action's Resolve-Path would expand; refusing to hand it a guess"
            )
        try:
            line = os.path.relpath(tree / entry["path"], catalog.parent)
        except ValueError as exc:  # different drive
            raise SignPlanError(f"catalog {catalog} cannot address {entry['path']}: {exc}") from exc
        lines.append(line)

    catalog.parent.mkdir(parents=True, exist_ok=True)
    catalog.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

    record = {
        "schema": PLAN_SCHEMA,
        "tree": str(tree),
        "catalog": str(catalog),
        "pe_count": len(files),
        "to_sign": to_sign,
        "kept": kept,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")

    print(f"::notice::SIGN PLAN: {len(files)} PE files -- {len(to_sign)} to sign, "
          f"{len(kept)} already carry a valid embedded signature and are KEPT as they are")
    for entry in to_sign:
        print(f"  sign  {entry['path']}  (embedded={entry['embedded']}, "
              f"Get-AuthenticodeSignature={entry['status']}/{entry['type'] or '-'})")
    for entry in kept:
        print(f"  keep  {entry['path']}  (CN={subject_cn(entry['subject'])})")
    return record


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def verify(tree, plan_path, expect_cn, out):
    tree = Path(tree).resolve()
    record = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    if record.get("schema") != PLAN_SCHEMA:
        raise SignPlanError(f"unknown plan schema {record.get('schema')!r} in {plan_path}")
    if not tree.is_dir():
        raise SignPlanError(f"frozen tree not found: {tree}")

    planned_sign = {e["path"]: e for e in record["to_sign"]}
    planned_keep = {e["path"]: e for e in record["kept"]}
    present = {rel(tree, p): p for p in pe_files(tree)}

    problems = []
    appeared = sorted(set(present) - set(planned_sign) - set(planned_keep))
    vanished = sorted((set(planned_sign) | set(planned_keep)) - set(present))
    if appeared:
        problems.append(f"PE file(s) not in the signing plan appeared after planning: {appeared}")
    if vanished:
        problems.append(f"planned PE file(s) vanished before verification: {vanished}")

    signatures = read_signatures(present.values())
    rows = []
    for name, path in sorted(present.items()):
        row = signatures[str(path)]
        role = "signed" if name in planned_sign else "kept" if name in planned_keep else "unplanned"
        rows.append({
            "path": name, "role": role,
            "status": row["status"], "type": row["type"],
            "embedded": hr_text(row), "signer": row["embedded_subject"],
        })
        if row["status"] != "Valid" or not embedded_valid(row):
            problems.append(
                f"{name}: not validly signed after signing (Get-AuthenticodeSignature="
                f"{row['status']}/{row['type'] or '-'}, embedded={hr_text(row)})"
            )
            continue
        if role == "kept":
            before = planned_keep[name]
            if row["embedded_thumbprint"] != before["thumbprint"]:
                problems.append(
                    f"{name}: its original signature was REPLACED -- signer was "
                    f"{before['subject']!r}, now {row['embedded_subject']!r}"
                )
        elif role == "signed":
            cn = subject_cn(row["embedded_subject"])
            if cn != expect_cn:
                problems.append(f"{name}: signed by CN={cn!r}, expected CN={expect_cn!r}")

    ours = sum(1 for r in rows if r["role"] == "signed")
    theirs = sum(1 for r in rows if r["role"] == "kept")
    report = {
        "passed": not problems,
        "problems": problems,
        "pe_count": len(rows),
        "signed_by_us": ours,
        "kept_third_party": theirs,
        "not_valid": sum(1 for r in rows if r["status"] != "Valid" or r["embedded"] != "Valid"),
        "expect_cn": expect_cn,
        "files": rows,
    }
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")

    for problem in problems:
        print(f"::error::SIGNATURE CHECK FAILED: {problem}", file=sys.stderr)
    if not problems:
        print(f"::notice::SIGNATURE CHECK OK: {len(rows)} PE files all Valid -- {ours} signed "
              f"CN={expect_cn}, {theirs} kept with their original publisher's signature")
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Sign only the PE files of a frozen tree that lack a valid signature."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_plan = sub.add_parser("plan", help="compute the signing set and write the files-catalog")
    p_plan.add_argument("--tree", required=True, help="the frozen one-dir tree")
    p_plan.add_argument("--catalog", required=True,
                        help="files-catalog to write (must be OUTSIDE the tree)")
    p_plan.add_argument("--out", required=True, help="plan JSON to write (OUTSIDE the tree)")

    p_verify = sub.add_parser("verify", help="prove every PE ends up validly signed")
    p_verify.add_argument("--tree", required=True, help="the signed frozen one-dir tree")
    p_verify.add_argument("--plan", required=True, help="the plan JSON `plan` wrote")
    p_verify.add_argument("--expect-cn", required=True,
                          help="CN every file in the signing set must now be signed by")
    p_verify.add_argument("--out", required=True, help="report JSON to write")

    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            plan(args.tree, args.catalog, args.out)
            return 0
        report = verify(args.tree, args.plan, args.expect_cn, args.out)
        return 0 if report["passed"] else 1
    except (SignPlanError, OSError, ValueError, KeyError) as exc:
        print(f"::error::SIGN PLAN FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
