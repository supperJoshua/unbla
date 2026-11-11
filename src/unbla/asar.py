"""Minimal, dependency-free Electron ``.asar`` reader/writer.

The format is a double Pickle header followed by a flat blob of file data:

    uint32  4                       outer pickle payload size
    uint32  word1 = 8 + len + pad    inner pickle size          -> data start = 8 + word1
    uint32  word2 = 4 + len + pad    inner pickle payload size
    uint32  word3 = len              JSON string length
    bytes   JSON + null padding
    bytes   file bodies, addressed by ``offset`` relative to data start

Offsets are relative to ``8 + word1``. This module only implements what a
forensic reader needs: enumerate, read, and rebuild without a subset of entries.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Callable, Iterator

PAD = 4


class AsarError(Exception):
    """Raised when an .asar file is structurally invalid."""


@dataclass(frozen=True)
class AsarEntry:
    path: str
    node: dict
    size: int


class AsarArchive:
    """A parsed .asar image. Bodies stay in memory so rebuilds are exact."""

    def __init__(self, raw: bytes) -> None:
        if len(raw) < 16:
            raise AsarError("file is too small to be an asar archive")
        self.raw = raw
        word0, word1, word2, word3 = struct.unpack("<4I", raw[:16])
        if word0 != 4:
            raise AsarError(f"unexpected outer pickle size {word0} (want 4)")
        self.header_size = word1
        self.json_size = word3
        self.data_start = 8 + word1
        if self.data_start > len(raw):
            raise AsarError("declared header runs past end of file")
        json_bytes = raw[16:16 + word3]
        try:
            self.header = json.loads(json_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AsarError(f"header is not valid JSON: {exc}") from exc
        if not isinstance(self.header.get("files"), dict):
            raise AsarError("header has no 'files' object")

    # -- reading ---------------------------------------------------------
    def entries(self) -> Iterator[AsarEntry]:
        yield from self._walk(self.header, "")

    def _walk(self, node: dict, prefix: str) -> Iterator[AsarEntry]:
        for name, child in node.get("files", {}).items():
            path = f"{prefix}/{name}" if prefix else name
            if "files" in child:
                yield from self._walk(child, path)
            else:
                yield AsarEntry(path, child, int(child.get("size", 0)))

    def read(self, entry: AsarEntry | str) -> bytes:
        if isinstance(entry, str):
            for cand in self.entries():
                if cand.path == entry.lstrip("/"):
                    entry = cand
                    break
            else:
                raise AsarError(f"no such entry: {entry}")
        if entry.node.get("unpacked"):
            raise AsarError(f"{entry.path} is unpacked (lives outside the archive)")
        start = self.data_start + int(entry.node.get("offset", 0))
        return self.raw[start:start + entry.size]

    @property
    def payload_bytes(self) -> int:
        return len(self.raw) - self.data_start

    def header_bytes(self) -> int:
        """Bytes the JSON header occupies, i.e. what admission limits measure."""
        return self.header_size


# -- writing -------------------------------------------------------------
def build_asar(
    header: dict,
    bodies: dict[str, bytes],
    keep: Callable[[str, dict], bool] | None = None,
) -> bytes:
    """Serialise ``header`` + ``bodies`` back into an asar image.

    ``keep`` filters (path, node) pairs; dropped entries are not copied into the
    payload, so both the header and the blob shrink. Offsets are recomputed in
    header order, which is what ``@electron/asar`` does on pack.
    """
    out_files: dict = {}
    payload = bytearray()

    def rebuild(node: dict, prefix: str) -> dict:
        files = {}
        for name, child in node.get("files", {}).items():
            path = f"{prefix}/{name}" if prefix else name
            if "files" in child:
                sub = rebuild(child, path)
                if sub["files"]:
                    files[name] = sub
                continue
            if keep is not None and not keep(path, child):
                continue
            if child.get("unpacked"):
                files[name] = child
                continue
            body = bodies.get(path, b"")
            new = dict(child)
            new["offset"] = str(len(payload))
            new["size"] = len(body)
            payload.extend(body)
            files[name] = new
        return {"files": files}

    out_files = rebuild(header, "")
    json_bytes = json.dumps(out_files, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    padding = (-len(json_bytes)) % PAD
    padded = json_bytes + (b"\x00" * padding)

    word1 = 8 + len(padded)
    word2 = 4 + len(padded)
    header_blob = struct.pack("<4I", 4, word1, word2, len(json_bytes)) + padded
    return header_blob + bytes(payload)
