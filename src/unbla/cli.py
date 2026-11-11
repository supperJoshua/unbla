"""Command line entry point: ``unbla scan | strip | verify``."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from . import shields, verify
from .asar import AsarArchive, build_asar

SCAN_SUFFIXES = {".asar", ".js", ".cjs", ".mjs", ".map", ".html", ".htm"}


def _iter_targets(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    out: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in SCAN_SUFFIXES:
            out.append(path)
    return out


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def scan_path(path: Path) -> list[shields.Finding]:
    suffix = path.suffix.lower()
    findings: list[shields.Finding] = []
    if suffix == ".asar":
        try:
            found, _ = shields.scan_asar(str(path))
            findings += found
        except Exception as exc:  # malformed archive is a finding, not a crash
            findings.append(shields.Finding(
                shield="unreadable-asar", target=str(path),
                detail=f"could not parse: {exc}", severity="warn"))
    elif suffix == ".map":
        found, _ = shields.scan_map(str(path))
        findings += found
    elif suffix in {".js", ".cjs", ".mjs", ".html", ".htm"}:
        try:
            found, _ = shields.scan_js(str(path))
            findings += found
        except OSError as exc:
            findings.append(shields.Finding(
                shield="unreadable", target=str(path),
                detail=str(exc), severity="warn"))
    return findings


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    targets = _iter_targets(root)
    all_findings: list[shields.Finding] = []
    for target in targets:
        all_findings += scan_path(target)

    report = {
        "tool": "unbla",
        "target": str(root),
        "files_scanned": len(targets),
        "findings": [f.as_dict() for f in all_findings],
        "shields": sorted({f.shield for f in all_findings}),
    }
    if args.json:
        print(json.dumps(report, indent=1, ensure_ascii=False))
    else:
        _print_findings(all_findings, len(targets))
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=1, ensure_ascii=False))
    return 1 if any(f.severity == "critical" for f in all_findings) else 0


def _print_findings(findings: list[shields.Finding], scanned: int) -> None:
    print(f"unbla scan — {scanned} file(s)")
    if not findings:
        print("no shield artifacts detected")
        return
    for f in findings:
        mark = {"critical": "!!", "warn": "! ", "info": ". "}[f.severity]
        print(f"{mark} [{f.shield}] {f.target}")
        print(f"    {f.detail}")
        if f.evidence:
            print(f"    evidence: {', '.join(str(e) for e in f.evidence)}")
    critical = sum(1 for f in findings if f.severity == "critical")
    warn = sum(1 for f in findings if f.severity == "warn")
    print()
    print(f"summary: {critical} critical, {warn} warning")


def cmd_strip(args: argparse.Namespace) -> int:
    root = Path(args.path)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    targets = _iter_targets(root)

    touched = 0
    dropped_entries = 0
    dropped_statements = 0
    dropped_maps = 0

    for target in targets:
        rel = _rel(target, root if root.is_dir() else root.parent)
        dest = out_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        suffix = target.suffix.lower()

        if suffix == ".asar":
            try:
                with open(target, "rb") as fh:
                    archive = AsarArchive(fh.read())
            except Exception:
                shutil.copy2(target, dest)
                continue
            bodies = {}
            decoys = set()
            for entry in archive.entries():
                if entry.node.get("unpacked"):
                    continue
                bodies[entry.path] = archive.read(entry)
                if shields._is_decoy_entry(entry.path, bodies[entry.path]):
                    decoys.add(entry.path)

            def keep(path: str, node: dict, decoys: set = decoys) -> bool:
                return path not in decoys

            dest.write_bytes(build_asar(archive.header, bodies, keep))
            dropped_entries += len(decoys)
            touched += 1
            continue

        if suffix in {".js", ".cjs", ".mjs", ".html", ".htm"}:
            try:
                source = target.read_text(encoding="utf-8", errors="replace")
                new_source, statements, maps = shields.strip_js(source)
            except OSError:
                shutil.copy2(target, dest)
                continue
            if new_source != source:
                dest.write_text(new_source, encoding="utf-8")
                dropped_statements += statements
                dropped_maps += maps
                touched += 1
            else:
                shutil.copy2(target, dest)
            continue

        if suffix == ".map":
            found, obj = shields.scan_map(str(target))
            if obj is not None and any(f.shield == "honey-sourcemap" for f in found):
                dropped_maps += 1  # fabricated provenance: emitting it is worse than omitting it
                touched += 1
                continue

        shutil.copy2(target, dest)

    print(f"unbla strip — {touched} file(s) modified")
    print(f"  asar decoy entries removed : {dropped_entries}")
    print(f"  decoy statements removed   : {dropped_statements}")
    print(f"  inline honey maps removed  : {dropped_maps}")
    print(f"  output                     : {out_dir}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    told = Path(args.original)
    new = Path(args.stripped)
    ok = True
    for target in sorted(told.rglob("*")):
        if not target.is_file():
            continue
        rel = target.relative_to(told)
        counterpart = new / rel
        if not counterpart.exists():
            continue
        suffix = target.suffix.lower()
        if suffix == ".asar":
            res = verify.verify_asar(str(target), str(counterpart))
            label = f"[asar] {rel}"
        elif suffix in {".js", ".cjs", ".mjs"}:
            if target.read_bytes() == counterpart.read_bytes():
                continue
            res = verify.verify_js(str(target), str(counterpart))
            label = f"[js]   {rel}"
        else:
            continue
        print(label)
        for line in res.lines:
            print(f"  {line}")
        ok = ok and res.ok
    print()
    print("RESULT:", "PASS — stripping is behaviour-preserving" if ok else "FAIL")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="unbla",
        description="Detect and strip the adversarial decoy layers that BLA-style "
                    "shields inject into release artifacts.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="report shield artifacts without modifying anything")
    p_scan.add_argument("path")
    p_scan.add_argument("--json", action="store_true", help="machine readable report")
    p_scan.add_argument("-o", "--out", help="also write the JSON report here")
    p_scan.set_defaults(func=cmd_scan)

    p_strip = sub.add_parser("strip", help="write a decoy-free copy of the artifact tree")
    p_strip.add_argument("path")
    p_strip.add_argument("-o", "--out", required=True, help="output directory")
    p_strip.set_defaults(func=cmd_strip)

    p_verify = sub.add_parser("verify", help="check that stripping preserved behaviour")
    p_verify.add_argument("original")
    p_verify.add_argument("stripped")
    p_verify.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
