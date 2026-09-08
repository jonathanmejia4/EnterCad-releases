# EnterCad — releases

This repository publishes EnterCad. It holds no source: the code lives in a
private repository and every artifact below is built, signed and published by
[`.github/workflows/release.yml`](.github/workflows/release.yml) on a hosted
Windows runner, from one `v*` tag.

EnterCad is an MCP server that gives an agent hands inside a desktop CAD
application (Autodesk Inventor today; the tool vocabulary is backend-neutral).

## Install

Pick one channel. The pip wheel is the primary channel; the frozen bundle is
the fallback for machines with no Python.

From PyPI:

```
pip install entercad
```

From a GitHub Release wheel:

```
pip install <Release wheel URL>
```

Copy the wheel URL out of the Assets list of the release you want.

### No Python on the machine

Download `entercad-<version>-win64.zip` from the release, unzip it anywhere,
and use the `entercad.exe` inside it wherever the steps below say `entercad`.
The bundle carries its own Python runtime. It is Authenticode-signed, so
Windows Smart App Control and SmartScreen let it run.

## Connect it to your agent

1. Run `entercad doctor`. It resolves your configuration and prints an MCP
   server block.
2. Paste that printed block into your agent's MCP configuration.
3. Reconnect the server in your agent; reconnecting makes it pick up the new
   configuration.
4. Run `entercad doctor` again and keep going until every check is green.

You need a working CAD seat on the same machine. `entercad doctor` names the
missing piece and the remedy for every check that is not green.

## Updating

`entercad update` checks the manifest published with each release and tells you
what changed. Reconnect the server in your agent afterwards.

## What each asset is

| Asset | What it is |
| --- | --- |
| `entercad-<version>-py3-none-any.whl` | The pip wheel — the **primary** channel. `pip install <this URL>` installs the `entercad` command and the `cadmcp` package. Requires Python 3.12+. |
| `entercad-<version>-win64.zip` | The **fallback** channel: a signed PyInstaller one-dir bundle for 64-bit Windows. Unzip and run `entercad\entercad.exe` — no Python needed. |
| `manifest.json` | The update manifest. It carries this release's version, the schema version and the publisher's supported-schema floor, the download URL and SHA-256 of both artifacts above, and the table of tool names with the version each was introduced in (removed names stay in the table, tombstoned). The installed server reads it to answer "am I current?" and "what happened to this tool?". |

Every `.exe`, `.dll` and `.pyd` in the frozen bundle is signed with Azure
Trusted Signing (publisher CN "Jonathan Mejia", RFC-3161 timestamped). The
signing step is unconditional: a release that could not be signed is never
published.

## Verifying a download

`manifest.json` carries the SHA-256 of both artifacts:

```
python -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" <file>
```

Compare it against `artifacts.wheel.sha256` or `artifacts.frozen.sha256` in
`manifest.json` from the same release.
