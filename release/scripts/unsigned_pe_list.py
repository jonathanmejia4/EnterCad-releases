#!/usr/bin/env python3
"""F11b — sign ONLY the PE files that do not already carry a valid signature.

This script is versioned in the SOURCE repo and *copied* into the public
releases repo alongside ``release.yml``, ``boot_proof.py`` and
``build_manifest.py``. The release workflow runs it twice, around the Azure
Trusted Signing step:

``plan``   (before signing) walks the frozen one-dir tree, asks Windows about
           the Authenticode signature of every PE file and splits them:

             * KEPT    -- carries a valid EMBEDDED Authenticode signature
                          (python312.dll from the PSF, VCRUNTIME140.dll from
                          Microsoft, ...). These are left byte-for-byte as they
                          are: re-signing them replaces their publisher's
                          signature with ours, which is what v0.1.0's
                          whole-folder sweep did to 45 Microsoft-signed
                          C-runtime files. The plan records each one's signer
                          thumbprint AND its SHA-256, and ``verify`` requires
                          both to be unchanged, so "left as they are" is
                          measured, not asserted.
             * TO SIGN -- everything else: no signature, a broken one (bad
                          digest, untrusted root, expired without a timestamp),
                          or validity that exists only as an entry in the build
                          machine's Windows catalog database -- that does not
                          travel with the file to a user's machine.
                          entercad.exe is always here: it is built on the
                          runner.

           It writes the TO SIGN list as the signing action's ``files-catalog``
           (paths relative to the catalog's own folder, one per line, no blank
           lines -- the format the pinned action's TrustedSigning module reads
           with Join-Path + Resolve-Path) and a JSON plan.

``verify`` (after signing) re-reads every PE in the tree and fails unless the
           set of PE files is exactly the planned set; every one carries a valid
           embedded signature; every KEPT file still has the SAME signer
           thumbprint and the SAME SHA-256 it had before signing; and every TO
           SIGN file is now signed by ``--expect-cn``. That is the Smart App
           Control invariant: every PE ends up with either its original valid
           signature or ours, and never ours in place of someone else's.

WHAT COUNTS AS A PE HERE. Enumeration is by CONTENT -- every file whose first
two bytes are ``MZ`` -- plus every file named ``.exe``/``.dll``/``.pyd`` (the
extensions the old files-folder sweep signed). Enumerating by extension alone
left a hole: a PE under any other name would appear in neither list, so it
would be neither signed nor checked, and would reach a user unsigned.

WHY NO POWERSHELL. Everything here is read through ctypes:

  * the KEEP/SIGN decision is ``WinVerifyTrust`` with ``WTD_CHOICE_FILE`` --
    the file's own EMBEDDED signature, never a catalog. A catalog answer would
    be wrong twice over: ``Get-AuthenticodeSignature`` consults the machine
    catalog FIRST and so reports VCRUNTIME140.dll as Valid/Catalog although it
    carries Microsoft's embedded signature (classifying on that answer
    re-signs it -- the very defect this script exists to remove), and a catalog
    hit on the builder says nothing about the user's machine;
  * the signer's subject and thumbprint come from ``CryptQueryObject`` +
    ``CertFindCertificateInStore``.

``Get-AuthenticodeSignature`` was used for the status string at first, and that
made this script depend on PowerShell cmdlet autoloading: on a hosted
windows-latest runner, a powershell.exe child of a pwsh parent inherits a
PSModulePath that does not resolve Microsoft.PowerShell.Security, and the
cmdlet fails with CouldNotAutoloadMatchingModule. The status string is derived
from the WinVerifyTrust result instead, which is the answer that actually
decides, so there is no cmdlet to autoload and no shell to be launched from.

Stdlib only. Windows only: there is no other way to ask the question this
script asks, so on any other platform it fails closed.

Exit codes: 0 on success; 1 on any violation or unreadable input (every
violation is named, as a GitHub ``::error::`` line).
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import sys
from pathlib import Path

# The extensions the replaced files-folder sweep signed. Enumeration is by MZ
# header as well, so a PE under any other name is still found.
PE_SUFFIXES = (".exe", ".dll", ".pyd")

PE_MAGIC = b"MZ"

# The pinned signing action resolves every catalog line with Resolve-Path,
# which treats these as wildcard syntax -- the backtick is PowerShell's escape
# character, so a name carrying one could resolve to a DIFFERENT file. A name
# with any of them is refused, never escaped.
WILDCARD_CHARS = frozenset("[]*?`")

PLAN_SCHEMA = 2

# WinVerifyTrust results worth naming. Anything else is reported as its hex.
TRUST_STATUS = {
    0x00000000: "Valid",
    0x800B0001: "TRUST_E_PROVIDER_UNKNOWN",
    0x800B0002: "TRUST_E_ACTION_UNKNOWN",
    0x800B0003: "TRUST_E_SUBJECT_FORM_UNKNOWN",
    0x800B0004: "TRUST_E_SUBJECT_NOT_TRUSTED",
    0x800B0100: "TRUST_E_NOSIGNATURE",
    0x800B0101: "CERT_E_EXPIRED",
    0x800B0109: "CERT_E_UNTRUSTEDROOT",
    0x800B010A: "CERT_E_CHAINING",
    0x800B010C: "CERT_E_REVOKED",
    0x800B0110: "CERT_E_WRONG_USAGE",
    0x800B0111: "CERT_E_EXPLICIT_DISTRUST",
    0x80096010: "TRUST_E_BAD_DIGEST",
    0x80092003: "CRYPT_E_FILE_ERROR",
}


class SignPlanError(Exception):
    """A named reason this tree cannot be planned or verified."""


# The Win32 type aliases this file needs, spelled out rather than imported
# from ctypes.wintypes: that module is not importable on every platform (its
# VARIANT_BOOL is unconditional), and this file must IMPORT anywhere -- the
# test suite reads it on Linux too. It fails closed at the first Windows call
# instead, in _windows_libraries().
_DWORD = ctypes.c_ulong
_WORD = ctypes.c_ushort
_HANDLE = ctypes.c_void_p
_LPCWSTR = ctypes.c_wchar_p
_LPWSTR = ctypes.c_wchar_p


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", _DWORD), ("dwHighDateTime", _DWORD)]


# ---------------------------------------------------------------------------
# Authenticode, read through ctypes (no shell, no cmdlet, no module to load)
# ---------------------------------------------------------------------------

class _GUID(ctypes.Structure):
    _fields_ = [("Data1", _DWORD), ("Data2", _WORD),
                ("Data3", _WORD), ("Data4", ctypes.c_ubyte * 8)]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", _DWORD),
                ("pcwszFilePath", _LPCWSTR),
                ("hFile", _HANDLE),
                ("pgKnownSubject", ctypes.c_void_p)]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", _DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", _DWORD),
                ("fdwRevocationChecks", _DWORD),
                ("dwUnionChoice", _DWORD),
                ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
                ("dwStateAction", _DWORD),
                ("hWVTStateData", _HANDLE),
                ("pwszURLReference", _LPWSTR),
                ("dwProvFlags", _DWORD),
                ("dwUIContext", _DWORD),
                ("pSignatureSettings", ctypes.c_void_p)]


class _CRYPT_BLOB(ctypes.Structure):
    _fields_ = [("cbData", _DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


class _CRYPT_ALGORITHM_IDENTIFIER(ctypes.Structure):
    _fields_ = [("pszObjId", ctypes.c_char_p), ("Parameters", _CRYPT_BLOB)]


class _CRYPT_BIT_BLOB(ctypes.Structure):
    _fields_ = [("cbData", _DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
                ("cUnusedBits", _DWORD)]


class _CERT_PUBLIC_KEY_INFO(ctypes.Structure):
    _fields_ = [("Algorithm", _CRYPT_ALGORITHM_IDENTIFIER), ("PublicKey", _CRYPT_BIT_BLOB)]


class _CRYPT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("cAttr", _DWORD), ("rgAttr", ctypes.c_void_p)]


class _CMSG_SIGNER_INFO(ctypes.Structure):
    _fields_ = [("dwVersion", _DWORD),
                ("Issuer", _CRYPT_BLOB),
                ("SerialNumber", _CRYPT_BLOB),
                ("HashAlgorithm", _CRYPT_ALGORITHM_IDENTIFIER),
                ("HashEncryptionAlgorithm", _CRYPT_ALGORITHM_IDENTIFIER),
                ("EncryptedHash", _CRYPT_BLOB),
                ("AuthAttrs", _CRYPT_ATTRIBUTES),
                ("UnauthAttrs", _CRYPT_ATTRIBUTES)]


class _CERT_INFO(ctypes.Structure):
    _fields_ = [("dwVersion", _DWORD),
                ("SerialNumber", _CRYPT_BLOB),
                ("SignatureAlgorithm", _CRYPT_ALGORITHM_IDENTIFIER),
                ("Issuer", _CRYPT_BLOB),
                ("NotBefore", _FILETIME),
                ("NotAfter", _FILETIME),
                ("Subject", _CRYPT_BLOB),
                ("SubjectPublicKeyInfo", _CERT_PUBLIC_KEY_INFO),
                ("IssuerUniqueId", _CRYPT_BIT_BLOB),
                ("SubjectUniqueId", _CRYPT_BIT_BLOB),
                ("cExtension", _DWORD),
                ("rgExtension", ctypes.c_void_p)]


class _CERT_CONTEXT(ctypes.Structure):
    _fields_ = [("dwCertEncodingType", _DWORD),
                ("pbCertEncoded", ctypes.POINTER(ctypes.c_ubyte)),
                ("cbCertEncoded", _DWORD),
                ("pCertInfo", ctypes.POINTER(_CERT_INFO)),
                ("hCertStore", ctypes.c_void_p)]


_WINTRUST_ACTION_GENERIC_VERIFY_V2 = _GUID(
    0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)

_CERT_QUERY_OBJECT_FILE = 0x00000001
_CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
_CERT_QUERY_FORMAT_FLAG_BINARY = 1 << 1
_CMSG_SIGNER_INFO_PARAM = 6
_X509_ASN_ENCODING = 0x00000001
_PKCS_7_ASN_ENCODING = 0x00010000
_CERT_FIND_SUBJECT_CERT = 11 << 16
_CERT_X500_NAME_STR = 3
# Most-significant RDN first ("CN=..., O=..., C=US"), the order every other
# tool displays a subject in.
_CERT_NAME_STR_REVERSE_FLAG = 0x02000000
_CERT_SHA1_HASH_PROP_ID = 3


_LIBRARIES = []


def _windows_libraries():
    """(wintrust, crypt32), loaded once. Fails closed off Windows."""
    if not _LIBRARIES:
        if not sys.platform.startswith("win"):
            raise SignPlanError(
                "Authenticode can only be read on Windows; refusing to guess a signing set"
            )
        try:
            wintrust = ctypes.WinDLL("wintrust.dll")
            crypt32 = ctypes.WinDLL("crypt32.dll")
        except OSError as exc:  # pragma: no cover - a Windows without wintrust/crypt32
            raise SignPlanError(f"cannot load wintrust.dll/crypt32.dll: {exc}") from exc
        wintrust.WinVerifyTrust.argtypes = [_HANDLE, ctypes.POINTER(_GUID),
                                            ctypes.POINTER(_WINTRUST_DATA)]
        wintrust.WinVerifyTrust.restype = ctypes.c_long
        crypt32.CertFindCertificateInStore.restype = ctypes.POINTER(_CERT_CONTEXT)
        crypt32.CertFreeCertificateContext.argtypes = [ctypes.POINTER(_CERT_CONTEXT)]
        _LIBRARIES.extend((wintrust, crypt32))
    return _LIBRARIES[0], _LIBRARIES[1]


def verify_embedded_signature(path):
    """WinVerifyTrust over WTD_CHOICE_FILE: the file's OWN embedded signature,
    with no UI and no revocation lookup. -> HRESULT, 0 iff valid. A catalog is
    never consulted (that needs WTD_CHOICE_CATALOG)."""
    wintrust, _ = _windows_libraries()
    file_info = _WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(_WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = str(path)
    file_info.hFile = None
    file_info.pgKnownSubject = None

    data = _WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
    data.dwUIChoice = 2           # WTD_UI_NONE
    data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
    data.dwUnionChoice = 1        # WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = 1        # WTD_STATEACTION_VERIFY
    data.dwProvFlags = 0x10       # WTD_REVOCATION_CHECK_NONE

    action = _GUID.from_buffer_copy(_WINTRUST_ACTION_GENERIC_VERIFY_V2)
    result = wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    data.dwStateAction = 2        # WTD_STATEACTION_CLOSE
    wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    return result & 0xFFFFFFFF


def embedded_signer(path):
    """-> (subject, thumbprint) of the file's embedded signature's signer
    certificate, or ("", "") when it carries none."""
    _, crypt32 = _windows_libraries()
    encoding = _DWORD()
    content_type = _DWORD()
    format_type = _DWORD()
    store = ctypes.c_void_p()
    msg = ctypes.c_void_p()
    ok = crypt32.CryptQueryObject(
        _CERT_QUERY_OBJECT_FILE, ctypes.c_wchar_p(str(path)),
        _CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, _CERT_QUERY_FORMAT_FLAG_BINARY, 0,
        ctypes.byref(encoding), ctypes.byref(content_type), ctypes.byref(format_type),
        ctypes.byref(store), ctypes.byref(msg), None,
    )
    if not ok:
        return "", ""

    try:
        size = _DWORD()
        if not crypt32.CryptMsgGetParam(msg, _CMSG_SIGNER_INFO_PARAM, 0, None,
                                        ctypes.byref(size)):
            return "", ""
        buffer = ctypes.create_string_buffer(size.value)
        if not crypt32.CryptMsgGetParam(msg, _CMSG_SIGNER_INFO_PARAM, 0, buffer,
                                        ctypes.byref(size)):
            return "", ""
        signer = ctypes.cast(buffer, ctypes.POINTER(_CMSG_SIGNER_INFO)).contents

        wanted = _CERT_INFO()
        wanted.Issuer = signer.Issuer
        wanted.SerialNumber = signer.SerialNumber
        cert = crypt32.CertFindCertificateInStore(
            store, _X509_ASN_ENCODING | _PKCS_7_ASN_ENCODING, 0,
            _CERT_FIND_SUBJECT_CERT, ctypes.byref(wanted), None,
        )
        if not cert:
            return "", ""
        try:
            subject_blob = ctypes.byref(cert.contents.pCertInfo.contents.Subject)
            name_format = _CERT_X500_NAME_STR | _CERT_NAME_STR_REVERSE_FLAG
            length = crypt32.CertNameToStrW(_X509_ASN_ENCODING, subject_blob,
                                            name_format, None, 0)
            text = ctypes.create_unicode_buffer(length)
            crypt32.CertNameToStrW(_X509_ASN_ENCODING, subject_blob,
                                   name_format, text, length)
            subject = text.value

            hash_size = _DWORD(20)
            digest = ctypes.create_string_buffer(20)
            thumbprint = ""
            if crypt32.CertGetCertificateContextProperty(
                cert, _CERT_SHA1_HASH_PROP_ID, digest, ctypes.byref(hash_size)
            ):
                thumbprint = digest.raw[:hash_size.value].hex().upper()
            return subject, thumbprint
        finally:
            crypt32.CertFreeCertificateContext(cert)
    finally:
        if msg:
            crypt32.CryptMsgClose(msg)
        if store:
            crypt32.CertCloseStore(store, 0)


def read_signatures(paths):
    """-> {path: row} where row carries ``embedded_hr`` (WinVerifyTrust, 0 =
    valid), ``embedded_status`` (its name), ``embedded_subject``,
    ``embedded_thumbprint`` and ``sha256``."""
    rows = {}
    for path in paths:
        code = verify_embedded_signature(path)
        subject, thumbprint = embedded_signer(path) if code == 0 else ("", "")
        rows[str(path)] = {
            "embedded_hr": code,
            "embedded_status": status_text(code),
            "embedded_subject": subject,
            "embedded_thumbprint": thumbprint,
            "sha256": file_sha256(path),
        }
    return rows


def status_text(code):
    name = TRUST_STATUS.get(code)
    return name if name else f"0x{code:08X}"


def embedded_valid(row):
    """True iff the file's OWN embedded Authenticode signature verifies."""
    return row.get("embedded_hr") == 0


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def subject_cn(subject):
    """The CN of an X.500 subject string, or None."""
    for part in re.split(r",\s*(?=[A-Za-z][A-Za-z0-9.]*=)", subject or ""):
        key, sep, value = part.partition("=")
        if sep and key.strip().upper() == "CN":
            return value.strip().strip('"')
    return None


# ---------------------------------------------------------------------------
# reading the tree
# ---------------------------------------------------------------------------

def looks_like_pe(path):
    """True iff the file begins with the DOS 'MZ' magic."""
    try:
        with open(path, "rb") as handle:
            return handle.read(2) == PE_MAGIC
    except OSError:
        return False


def pe_files(tree):
    """Every PE file under ``tree``, sorted: anything whose content says PE (an
    MZ header) and anything named like one (.exe/.dll/.pyd), so neither an
    oddly-named PE nor a mis-named one can slip past both lists."""
    return sorted(
        p for p in Path(tree).rglob("*")
        if p.is_file() and (p.suffix.lower() in PE_SUFFIXES or looks_like_pe(p))
    )


def rel(tree, path):
    return Path(path).relative_to(tree).as_posix()


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
        raise SignPlanError(f"no PE files under {tree}")
    signatures = read_signatures(files)

    to_sign, kept = [], []
    for path in files:
        row = signatures[str(path)]
        entry = {"path": rel(tree, path), "embedded": row["embedded_status"]}
        if embedded_valid(row):
            entry.update(subject=row["embedded_subject"], thumbprint=row["embedded_thumbprint"],
                         sha256=row["sha256"])
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
                f"{entry['path']!r} contains wildcard/escape character(s) {bad} that the "
                "signing action's Resolve-Path would expand; refusing to hand it a guess"
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
        print(f"  sign  {entry['path']}  ({entry['embedded']})")
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
            "embedded": row["embedded_status"], "signer": row["embedded_subject"],
        })
        if not embedded_valid(row):
            problems.append(
                f"{name}: not validly signed after signing (embedded={row['embedded_status']})"
            )
            continue
        if role == "kept":
            before = planned_keep[name]
            if row["embedded_thumbprint"] != before["thumbprint"]:
                problems.append(
                    f"{name}: its original signature was REPLACED -- signer was "
                    f"{before['subject']!r}, now {row['embedded_subject']!r}"
                )
            elif row["sha256"] != before["sha256"]:
                problems.append(
                    f"{name}: a KEPT file was MODIFIED -- SHA-256 was {before['sha256']}, "
                    f"now {row['sha256']}"
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
        "not_valid": sum(1 for r in rows if r["embedded"] != "Valid"),
        "expect_cn": expect_cn,
        "files": rows,
    }
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")

    for problem in problems:
        print(f"::error::SIGNATURE CHECK FAILED: {problem}", file=sys.stderr)
    if not problems:
        print(f"::notice::SIGNATURE CHECK OK: {len(rows)} PE files all carry a valid embedded "
              f"signature -- {ours} signed CN={expect_cn}, {theirs} kept with their original "
              "publisher's signature, unmodified")
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
