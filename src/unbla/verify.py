"""Verification: prove that stripping did not change behaviour.

Three independent checks, all cheap and all falsifiable:

* **API surface** — the exported names of a JS module before and after strip.
* **Parseability** — ``node --check`` on the result (skipped if node is absent).
* **Payload fidelity** — SHA-256 of every surviving asar entry, before and after.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass

from .asar import AsarArchive

QUOTES = "'" + chr(34)


def _split_top(body: str) -> list[str]:
    """Split an object literal body on commas that are at nesting depth 0."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in body:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    if current:
        parts.append("".join(current))
    return parts


def exported_names(source: str) -> set[str]:
    """Names the module exposes. Decoy payload keys are never counted.

    Only ``module.exports = { ... }`` and top-level ``export`` declarations are
    considered, because those are the two shapes a loader can observe. A loose
    key:value scan over the whole file would happily pick up JSON decoy keys.
    """
    names: set[str] = set()
    idx = source.find("module.exports")
    if idx >= 0:
        brace = source.find("{", idx)
        if brace >= 0:
            depth = 0
            end = -1
            for pos in range(brace, len(source)):
                ch = source[pos]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = pos
                        break
            if end > brace:
                for part in _split_top(source[brace + 1:end]):
                    part = part.strip()
                    if not part:
                        continue
                    if ":" in part:
                        names.add(part.split(":", 1)[0].strip().strip(QUOTES))
                    else:
                        names.add(part.strip(QUOTES))
    if not names:
        for line in source.splitlines():
            words = line.strip().split()
            if len(words) < 2 or words[0] != "export":
                continue
            i = 1
            if words[i] == "default":
                i += 1
            if i < len(words) and words[i] == "async":
                i += 1
            if i < len(words) and words[i] in ("const", "let", "var", "function", "class"):
                i += 1
                if i < len(words):
                    candidate = words[i].split("=")[0].split("(")[0].strip()
                    if candidate and (candidate[0].isalpha() or candidate[0] in "_$"):
                        names.add(candidate)
    return names


def node_parses(path: str) -> tuple[bool | None, str]:
    node = shutil.which("node")
    if not node:
        return None, "node not available; parse check skipped"
    proc = subprocess.run([node, "--check", path], capture_output=True, text=True)
    return proc.returncode == 0, (proc.stderr.strip().splitlines() or [""])[0]


@dataclass
class VerifyResult:
    ok: bool
    lines: list[str]


def verify_js(orig: str, new: str) -> VerifyResult:
    with open(orig, encoding="utf-8", errors="replace") as fh:
        a = fh.read()
    with open(new, encoding="utf-8", errors="replace") as fh:
        b = fh.read()
    ok = True
    lines: list[str] = []

    before, after = exported_names(a), exported_names(b)
    if before != after:
        ok = False
        lines.append(f"FAIL exports changed: -{sorted(before - after)} +{sorted(after - before)}")
    else:
        lines.append(f"ok   exports identical ({len(before)} names)")

    parsed, note = node_parses(new)
    if parsed is False:
        ok = False
        lines.append(f"FAIL node --check: {note}")
    elif parsed is True:
        lines.append("ok   node --check passed")
    else:
        lines.append(f"skip {note}")

    reduction = 100 * (1 - len(b) / max(1, len(a)))
    lines.append(f"     size {len(a)} -> {len(b)} bytes ({reduction:.1f}% smaller)")
    return VerifyResult(ok, lines)


def verify_asar(orig: str, new: str) -> VerifyResult:
    with open(orig, "rb") as fh:
        before = AsarArchive(fh.read())
    with open(new, "rb") as fh:
        after = AsarArchive(fh.read())
    ok = True
    lines: list[str] = []

    survivors = {e.path: hashlib.sha256(before.read(e)).hexdigest()
                 for e in before.entries() if not e.node.get("unpacked")}
    remaining = {e.path: hashlib.sha256(after.read(e)).hexdigest()
                 for e in after.entries() if not e.node.get("unpacked")}

    # Decoy entries are *meant* to disappear; only real payload must survive.
    from .shields import _is_decoy_entry
    real = {p: h for p, h in survivors.items()
            if not _is_decoy_entry(p, before.read(p))}

    missing = sorted(set(real) - set(remaining))
    if missing:
        ok = False
        lines.append(f"FAIL real entries lost: {[m[:50] for m in missing[:5]]}")
    else:
        lines.append(f"ok   all {len(real)} real entries still present")

    changed = [p for p in real if p in remaining and real[p] != remaining[p]]
    if changed:
        ok = False
        lines.append(f"FAIL payload changed for: {[c[:50] for c in changed[:5]]}")
    else:
        lines.append("ok   every surviving real payload byte-identical")

    header_before = before.header_bytes()
    header_after = after.header_bytes()
    lines.append(f"     header {header_before / 1024 / 1024:.2f} MiB -> "
                 f"{header_after / 1024 / 1024:.2f} MiB")
    lines.append(f"     file   {len(before.raw) / 1024 / 1024:.2f} MiB -> "
                 f"{len(after.raw) / 1024 / 1024:.2f} MiB")
    return VerifyResult(ok, lines)
