#!/usr/bin/env python3
"""Release metadata for TheStandard (法仪).

This script is the single source of truth for the release contract consumed by
GhostReveal installers and RSLLM bundles:

    the-standard-service-<target>[.exe]   the five release binaries
    SHA256SUMS                            sha256 of every published file
    the-standard-release.json             machine-readable release manifest

Nothing is hardcoded here: the release version comes from the workspace
`Cargo.toml`, the schema/capability numbers from
`crates/the-standard-contracts/src/lib.rs`, and the README version matrix is
cross-checked against both.  A release therefore cannot go stale behind a
version bump.

Usage:
  release.py check-tag --workspace DIR --ref REF --event EVENT [--github-output FILE]
  release.py package   --workspace DIR --dist DIR --tag TAG --commit SHA \\
                       --notes-out FILE [--expect-target TRIPLE ...]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tomllib

CONTRACTS_LIB = pathlib.Path("crates/the-standard-contracts/src/lib.rs")
BINARY = "the-standard-service"
MANIFEST_NAME = "the-standard-release.json"
SUMS_NAME = "SHA256SUMS"


def fail(message: str) -> None:
    print(f"release.py: error: {message}", file=sys.stderr)
    raise SystemExit(1)


def log(message: str) -> None:
    print(f"release.py: {message}")


def workspace_version(root: pathlib.Path) -> str:
    manifest = root / "Cargo.toml"
    if not manifest.is_file():
        fail(f"{manifest} is missing")
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    try:
        version = data["workspace"]["package"]["version"]
    except KeyError:
        fail("Cargo.toml has no [workspace.package] version")
    if not isinstance(version, str):
        fail("[workspace.package] version must be a literal string")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        fail(f"workspace version {version!r} is not a plain SemVer triple")
    return version


def check_crate_versions(root: pathlib.Path, version: str) -> None:
    """Every crate must inherit the workspace version, or pin it identically."""
    for manifest in sorted(root.glob("crates/*/Cargo.toml")):
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        declared = data.get("package", {}).get("version")
        if isinstance(declared, dict) and declared.get("workspace") is True:
            continue
        if declared != version:
            fail(
                f"{manifest.relative_to(root)} declares version {declared!r} "
                f"but the workspace version is {version!r}"
            )


def contracts_source(root: pathlib.Path) -> str:
    path = root / CONTRACTS_LIB
    if not path.is_file():
        fail(f"{path} is missing")
    return path.read_text(encoding="utf-8")


def numeric_constant(source: str, name: str) -> int:
    match = re.search(rf"pub const {name}: u32 = (\d+);", source)
    if match is None:
        fail(f"crates/the-standard-contracts/src/lib.rs has no `pub const {name}: u32 = <n>;`")
    return int(match.group(1))


def string_constant(source: str, name: str) -> str:
    match = re.search(rf'pub const {name}: &str = "([^"]+)";', source)
    if match is None:
        fail(f'crates/the-standard-contracts/src/lib.rs has no `pub const {name}: &str = "<value>";`')
    return match.group(1)


def readme_matrix(root: pathlib.Path, version: str) -> dict[str, str]:
    """Return the README 'Current version matrix' row for `version`."""
    path = root / "README.md"
    if not path.is_file():
        fail(f"{path} is missing")
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip().strip("`") for cell in stripped.strip("|").split("|")]
        if cells and cells[0] == version:
            if len(cells) != 5:
                fail(f"README.md version matrix row for {version} has {len(cells)} cells, expected 5")
            return {
                "manifest": cells[1],
                "report": cells[2],
                "presentation": cells[3],
                "profile": cells[4],
            }
    fail(f"README.md 'Current version matrix' has no row for release {version}")


def release_identity(root: pathlib.Path) -> dict[str, object]:
    version = workspace_version(root)
    check_crate_versions(root, version)
    contracts = contracts_source(root)
    identity: dict[str, object] = {
        "version": version,
        "tag": f"v{version}",
        "reportSchemaVersion": numeric_constant(contracts, "REPORT_SCHEMA_VERSION"),
        "uiManifestSchemaVersion": numeric_constant(contracts, "UI_MANIFEST_SCHEMA_VERSION"),
        "presentationSchemaVersion": numeric_constant(contracts, "PRESENTATION_SCHEMA_VERSION"),
        "capabilityProfile": string_constant(contracts, "CORE_CAPABILITY_PROFILE"),
    }

    row = readme_matrix(root, version)
    expected = {
        "manifest": str(identity["uiManifestSchemaVersion"]),
        "report": str(identity["reportSchemaVersion"]),
        "presentation": str(identity["presentationSchemaVersion"]),
        "profile": str(identity["capabilityProfile"]),
    }
    if row != expected:
        fail(
            "README.md version matrix disagrees with Cargo.toml / the-standard-contracts: "
            f"README says {row}, source says {expected}"
        )
    return identity


def head_commit(root: pathlib.Path) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"cannot resolve the release commit: {error}")


def parse_tag(identity: dict[str, object], ref: str, event: str) -> str:
    """Validate the requested ref against `v<workspace version>`."""
    expected = str(identity["tag"])
    version = str(identity["version"])
    actual: str | None = None
    if ref.startswith("refs/tags/"):
        actual = ref[len("refs/tags/") :]
    elif re.fullmatch(r"v\d+\.\d+\.\d+", ref or ""):
        actual = ref
    if actual is not None:
        if actual != expected:
            fail(
                f"tag {actual!r} does not match the workspace version "
                f"{version!r}; tags must be exactly {expected!r}"
            )
        log(f"tag {expected} matches the workspace version {version}")
        return expected
    log(
        f"{event} on {ref or 'an empty ref'}: no tag was pushed, publishing "
        f"the workspace version {version} as {expected}"
    )
    return expected


def write_github_outputs(path: str, values: dict[str, object]) -> None:
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def command_check_tag(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.workspace).resolve()
    identity = release_identity(root)
    tag = parse_tag(identity, args.ref, args.event)
    commit = head_commit(root)
    outputs = {
        "version": identity["version"],
        "tag": tag,
        "commit": commit,
        "reportSchemaVersion": identity["reportSchemaVersion"],
        "uiManifestSchemaVersion": identity["uiManifestSchemaVersion"],
        "presentationSchemaVersion": identity["presentationSchemaVersion"],
        "capabilityProfile": identity["capabilityProfile"],
    }
    for key, value in outputs.items():
        log(f"{key}: {value}")
    if args.github_output:
        write_github_outputs(args.github_output, outputs)
    return 0


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def asset_name(target: str) -> str:
    suffix = ".exe" if target.endswith("-windows-msvc") else ""
    return f"{BINARY}-{target}{suffix}"


def command_package(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.workspace).resolve()
    dist = pathlib.Path(args.dist).resolve()
    if not dist.is_dir():
        fail(f"{dist} does not exist; the build artifacts were not downloaded")

    identity = release_identity(root)
    if args.tag != identity["tag"]:
        fail(
            f"release tag {args.tag!r} does not match the workspace version "
            f"{identity['version']!r} (expected {identity['tag']!r})"
        )
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        fail(f"commit {args.commit!r} is not a full 40-character git SHA")

    expected = {asset_name(target): target for target in args.expect_target}
    present: dict[str, pathlib.Path] = {}
    for entry in sorted(dist.iterdir()):
        if entry.name.startswith(".") or entry.is_dir():
            continue
        if entry.name in {MANIFEST_NAME, SUMS_NAME}:
            continue
        present[entry.name] = entry

    missing = sorted(set(expected) - set(present))
    if missing:
        fail(f"missing release assets: {', '.join(missing)}")
    unexpected = sorted(set(present) - set(expected))
    if unexpected:
        fail(f"unexpected files in {dist}: {', '.join(unexpected)}")

    assets = []
    for name, target in sorted(expected.items(), key=lambda item: item[1]):
        path = present[name]
        size = path.stat().st_size
        if size == 0:
            fail(f"{name} is empty")
        assets.append(
            {
                "target": target,
                "name": name,
                "sha256": sha256_file(path),
            }
        )
        log(f"asset {name} ({size} bytes) sha256={assets[-1]['sha256']}")

    manifest = {
        "version": identity["version"],
        "tag": identity["tag"],
        "commit": args.commit,
        "reportSchemaVersion": identity["reportSchemaVersion"],
        "uiManifestSchemaVersion": identity["uiManifestSchemaVersion"],
        "presentationSchemaVersion": identity["presentationSchemaVersion"],
        "capabilityProfile": identity["capabilityProfile"],
        "assets": assets,
    }
    manifest_path = dist / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    # SHA256SUMS covers every published file except SHA256SUMS itself, so
    # `sha256sum -c SHA256SUMS` also authenticates the JSON manifest.
    sums = []
    for entry in sorted(dist.iterdir()):
        if not entry.is_file() or entry.name == SUMS_NAME:
            continue
        sums.append(f"{sha256_file(entry)}  {entry.name}")
    (dist / SUMS_NAME).write_text("\n".join(sums) + "\n", encoding="utf-8")

    rows = "\n".join(
        f"| `{asset['target']}` | `{asset['name']}` | `{asset['sha256']}` |" for asset in assets
    )
    notes = f"""# 法仪（TheStandard）{identity['tag']}

Standalone `the-standard-service` binaries consumed by GhostReveal installers and RSLLM bundles.

- Commit: `{args.commit}`
- Rule snapshot: the service resolves its immutable rule bundle at runtime from
  [`MoBalance/SanBiao`](https://github.com/MoBalance/SanBiao) `manifest.json`; no rules are
  vendored into these binaries.

## Version matrix

| Core release | Manifest schema | Report schema | Presentation schema | Capability profile |
| --- | ---: | ---: | ---: | --- |
| `{identity['version']}` | `{identity['uiManifestSchemaVersion']}` | `{identity['reportSchemaVersion']}` | `{identity['presentationSchemaVersion']}` | `{identity['capabilityProfile']}` |

## Assets

| Target | Asset | SHA-256 |
| --- | --- | --- |
{rows}

## Verification

```sh
sha256sum -c SHA256SUMS          # shasum -a 256 -c SHA256SUMS on macOS
chmod +x the-standard-service-*  # the release assets are stored without a mode bit
```

`{MANIFEST_NAME}` repeats the version matrix and the per-asset digests for installer tooling.
Scores from different capability profiles are not comparable.
"""
    notes_path = pathlib.Path(args.notes_out)
    notes_path.parent.mkdir(parents=True, exist_ok=True)
    notes_path.write_text(notes, encoding="utf-8")
    log(f"wrote {manifest_path}, {dist / SUMS_NAME} and {notes_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check-tag", help="validate the release ref against the workspace version")
    check.add_argument("--workspace", default=".")
    check.add_argument("--ref", default="")
    check.add_argument("--event", default="")
    check.add_argument("--github-output", default="")
    check.set_defaults(func=command_check_tag)

    package = subparsers.add_parser("package", help="write the release manifest, checksums and notes")
    package.add_argument("--workspace", default=".")
    package.add_argument("--dist", required=True)
    package.add_argument("--tag", required=True)
    package.add_argument("--commit", required=True)
    package.add_argument("--notes-out", required=True)
    package.add_argument("--expect-target", action="append", default=[])
    package.set_defaults(func=command_package)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
