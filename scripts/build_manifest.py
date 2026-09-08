#!/usr/bin/env python3
"""C3a — build the update manifest for one EnterCad release.

This script is versioned in the SOURCE repo and *copied* into the public
releases repo alongside ``release.yml``; the workflow runs it after the wheel
and the signed frozen zip exist. It is deliberately tiny: stdlib + one import
of :mod:`cadmcp.manifest` (D1a), which owns the schema, the carry-forward rule
for ``version_introduced`` and the tombstoning of removed names. Nothing here
reaches the network — the artifact URLs are *computed* from the releases-repo
coordinate and the tag, never fetched.

The workflow runs it with ``PYTHONPATH=src`` so ``cadmcp`` resolves out of the
sparse checkout of the private source repo (the same tree the wheel was built
from), never out of a pip-installed copy.

Exit codes: 0 on success, 1 on any ``ManifestError`` or unreadable input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

# The releases repository is one of the two repository coordinates this campaign
# names (the other is the private source repo, which only the workflow touches).
# It is a default, not a hardcode: --releases-repo overrides it.
DEFAULT_RELEASES_REPO = "jonathanmejia4/EnterCad-releases"

_DOWNLOAD_URL = "https://github.com/{repo}/releases/download/v{version}/{name}"
_NOTES_URL = "https://github.com/{repo}/releases/tag/v{version}"

_CHUNK = 1 << 20


def sha256_of(path: Path) -> str:
    """Streaming sha256 of a file (the artifacts are hundreds of MB)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_tool_names(path: Path):
    """Read the tool-name list the workflow enumerated.

    Three shapes are accepted so the same file can come from either source the
    workflow uses: the stdio enumeration of the BUILT wheel (a plain JSON list
    of names) or the ``baseline/tools-baseline.json`` fallback (an object whose
    ``tools`` key holds the full tool descriptors).
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("tools", [])
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON list of tool names")
    names = []
    for entry in data:
        if isinstance(entry, str):
            names.append(entry)
        elif isinstance(entry, dict) and isinstance(entry.get("name"), str):
            names.append(entry["name"])
        else:
            raise ValueError(f"{path}: entry is neither a name nor a tool object: {entry!r}")
    return names


def _artifact(repo: str, version: str, path: Path) -> dict:
    return {
        "url": _DOWNLOAD_URL.format(repo=repo, version=version, name=path.name),
        "sha256": sha256_of(path),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build_manifest.py",
        description="Build manifest.json for one EnterCad release.",
    )
    parser.add_argument("--wheel", required=True, help="path to the built wheel")
    parser.add_argument("--zip", required=True, dest="zip_path",
                        help="path to the signed frozen one-dir zip")
    parser.add_argument("--version", required=True, help="release version, no leading v")
    parser.add_argument("--previous", default=None,
                        help="path to the previous release's manifest.json, if any")
    parser.add_argument("--tools-json", required=True,
                        help="JSON file holding this release's tool names")
    parser.add_argument("--removed", action="append", default=[],
                        help="a tool name removed in this release (repeatable)")
    parser.add_argument("--releases-repo", default=DEFAULT_RELEASES_REPO,
                        help="owner/name of the public releases repository")
    parser.add_argument("--out", required=True, help="where to write manifest.json")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    # Imported here (not at module scope) so --help works even where cadmcp is
    # not importable, and so an import failure reports as this script's error.
    from cadmcp.manifest import ManifestError, build_manifest, load_manifest, validate_manifest

    wheel_path = Path(args.wheel)
    zip_path = Path(args.zip_path)
    for label, path in (("wheel", wheel_path), ("zip", zip_path)):
        if not path.is_file():
            print(f"::error::MANIFEST BUILD FAILED: --{label} does not exist: {path}",
                  file=sys.stderr)
            return 1

    try:
        tool_names = read_tool_names(Path(args.tools_json))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"::error::MANIFEST BUILD FAILED: unreadable --tools-json: {exc}", file=sys.stderr)
        return 1

    previous = None
    if args.previous:
        previous_path = Path(args.previous)
        try:
            previous = load_manifest(previous_path.read_text(encoding="utf-8"))
        except ManifestError as exc:
            print(f"::error::MANIFEST BUILD FAILED: previous manifest rejected ({exc.reason})",
                  file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"::error::MANIFEST BUILD FAILED: unreadable --previous: {exc}", file=sys.stderr)
            return 1

    repo = args.releases_repo
    version = args.version
    artifacts = {
        "wheel": _artifact(repo, version, wheel_path),
        "frozen": _artifact(repo, version, zip_path),
    }

    try:
        manifest = build_manifest(
            tool_names,
            previous_manifest=previous,
            removed=args.removed,
            artifacts=artifacts,
            version=version,
            notes_url=_NOTES_URL.format(repo=repo, version=version),
        )
        validate_manifest(manifest)
    except ManifestError as exc:
        print(f"::error::MANIFEST BUILD FAILED: {exc.reason}", file=sys.stderr)
        return 1

    out_path = Path(args.out)
    if out_path.parent != Path(""):
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"manifest.json written: {out_path} "
          f"(version {manifest['version']}, {len(manifest['tools'])} tools)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
