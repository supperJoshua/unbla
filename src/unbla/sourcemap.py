"""SourceMap v3 helpers focused on *fabricated* pretty-printed maps.

A real compiler emits many distinct VLQ segments. Decoy ("honey") maps instead
reuse a tiny set of segments, point at sources that never existed, and often
carry decoy-tool fingerprints in ``sourceRoot``/``sourcesContent``. Those are
cheap, reliable invariants — no heuristics about "looks odd" required.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field

B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# A compile-time map for a 100+ line file cannot legitimately have < 8 distinct segments.
MIN_DISTINCT_SEGMENTS = 8
MIN_LINES_FOR_RATIO_CHECK = 40


@dataclass
class MapVerdict:
    fabricated: bool
    reasons: list[str] = field(default_factory=list)
    distinct_segments: int = 0
    total_segments: int = 0


def decode_vlq(value: str) -> list[int]:
    """Decode one VLQ field into its raw integers."""
    out: list[int] = []
    shift = 0
    acc = 0
    for ch in value:
        digit = B64_CHARS.find(ch)
        if digit < 0:
            raise ValueError(f"invalid base64 VLQ character {ch!r}")
        cont = digit & 32
        acc += (digit & 31) << shift
        if cont:
            shift += 5
            continue
        negative = acc & 1
        acc >>= 1
        out.append(-acc if negative else acc)
        acc = 0
        shift = 0
    return out


def segments_of(mappings: str) -> list[str]:
    """Return every non-empty VLQ segment string in a map, in order."""
    segments: list[str] = []
    for line in mappings.split(";"):
        for seg in line.split(","):
            if seg:
                segments.append(seg)
    return segments


def judge(map_obj: dict) -> MapVerdict:
    """Classify a parsed sourcemap as fabricated or plausible."""
    reasons: list[str] = []
    mappings = map_obj.get("mappings") or ""
    segs = segments_of(mappings)
    distinct = len(set(segs))
    verdict = MapVerdict(False, reasons, distinct, len(segs))

    root = str(map_obj.get("sourceRoot") or "")
    sources = [str(s) for s in (map_obj.get("sources") or [])]
    contents = map_obj.get("sourcesContent") or []

    if re.match("^[a-z]+://", root):
        reasons.append(f"sourceRoot is a synthetic scheme: {root}")

    if sources and all(re.search("/(enclave|tee|attestation|compat)/", s) for s in sources):
        reasons.append("all sources live under enclave/TEE fixture paths")

    if contents and all(isinstance(c, str) and len(c) < 400 for c in contents):
        reasons.append("sourcesContent are short stubs, not whole modules")

    if len(segs) >= MIN_LINES_FOR_RATIO_CHECK and distinct <= 3:
        reasons.append(
            f"mappings reuse {distinct} distinct segment(s) across {len(segs)} segments"
        )

    if len(segs) < MIN_LINES_FOR_RATIO_CHECK and distinct <= 2 and len(segs) >= 2:
        reasons.append(f"tiny repeated mapping run ({distinct} distinct of {len(segs)})")

    verdict.fabricated = len(reasons) >= 2
    return verdict


WSCHARS = " " + chr(9) + chr(13) + chr(10)
INLINE_DIRECTIVE = re.compile(
    "//[#@][" + WSCHARS + "]*"
    "sourceMappingURL=data:application/json[^," + WSCHARS + "]*"
    ";base64,([A-Za-z0-9+/=]+)"
)


def inline_payloads(text: str) -> list[tuple[str, dict]]:
    """Yield (directive, decoded map) for inline base64 sourcemaps."""
    found: list[tuple[str, dict]] = []
    for match in INLINE_DIRECTIVE.finditer(text):
        blob = match.group(1)
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8")
            obj = json.loads(decoded)
        except (ValueError, json.JSONDecodeError):
            continue
        if isinstance(obj, dict):
            found.append((match.group(0), obj))
    return found
