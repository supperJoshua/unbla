"""Tests for unbla. Every fixture is built inline, so the suite is self-contained."""

import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from unbla import jsast, shields, sourcemap, verify  # noqa: E402
from unbla.asar import AsarArchive, build_asar  # noqa: E402

DECOY_PATH = "enclave/shards/ring0-slot-a1b-" + ("a" * 40) + "_3.json"
DECOY_BODY = json.dumps({"shardId": "s-3", "enclaveCid": "c" * 16,
                         "attestationHash": "h" * 32, "delegated": True}).encode()
REAL_BODY = b"module.exports = { seatCost: 1 };\n"

FABRICATED_MAP = {
    "version": 3,
    "sourceRoot": "enclave://tee-runtime/",
    "sources": ["src/enclave/hardware-tpm2-bridge-11.ts"],
    "sourcesContent": ["export const x = 1;"],
    "mappings": ",".join(["AAAA"] * 500),
}
REAL_MAP = {
    "version": 3,
    "sources": ["../src/billing.ts"],
    "sourcesContent": ["export function seatCost(t: number) { return t * 4; }\n" * 40],
    "mappings": ";".join(
        ",".join(f"{n}AA{n}" for n in range(6)) for _ in range(12)
    ),
}

WOVEN_JS = (
    "const _interlockSafetyCorpus_0c43 = { a: 1, b: 2 };\n"
    "function _deriveContainmentCorpusDigest_0c43(x) { return x.a + x.b; }\n"
    "function runtimeSeedPrimaryPolicy_5a85() {\n"
    "  return _deriveContainmentCorpusDigest_0c43(_interlockSafetyCorpus_0c43);\n"
    "}\n"
    "module.exports = { runtimeSeedPrimaryPolicy_5a85 };\n"
)

ISOLATED_JS = (
    "function _alignmentArmor_9f2() { return 42; }\n"
    "module.exports = { seatCost: 1 };\n"
)


class AsarRoundTrip(unittest.TestCase):
    def _image(self):
        header = {"files": {
            "dist": {"files": {
                "main.js": {"size": len(REAL_BODY), "offset": "0"},
            }},
            "enclave": {"files": {
                "shards": {"files": {
                    "ring0-slot-a1b-" + "a" * 40 + "_3.json": {
                        "size": len(DECOY_BODY), "offset": str(len(REAL_BODY))},
                }},
            }},
        }}
        bodies = {"dist/main.js": REAL_BODY, DECOY_PATH: DECOY_BODY}
        return header, bodies

    def test_round_trip_preserves_payload(self):
        header, bodies = self._image()
        blob = build_asar(header, bodies)
        archive = AsarArchive(blob)
        self.assertEqual(archive.read("dist/main.js"), REAL_BODY)
        self.assertGreater(archive.header_bytes(), 0)

    def test_strip_drops_only_decoys(self):
        header, bodies = self._image()
        blob = build_asar(header, bodies)
        archive = AsarArchive(blob)
        kept = build_asar(archive.header, bodies,
                          lambda p, n: not shields._is_decoy_entry(p, bodies.get(p, b"")))
        after = AsarArchive(kept)
        paths = [e.path for e in after.entries()]
        self.assertIn("dist/main.js", paths)
        self.assertNotIn(DECOY_PATH, paths)
        self.assertEqual(after.read("dist/main.js"), REAL_BODY)


class DecoyDetection(unittest.TestCase):
    def test_path_shape(self):
        self.assertTrue(shields._is_decoy_entry(DECOY_PATH, b""))

    def test_body_shape_without_path(self):
        self.assertTrue(shields._is_decoy_entry("resources/x.json", DECOY_BODY))

    def test_real_file_is_not_decoy(self):
        self.assertFalse(shields._is_decoy_entry("dist/main.js", REAL_BODY))
        self.assertFalse(shields._is_decoy_entry("resources/x.json", json.dumps({"total": 3}).encode()))


class SourceMapForensics(unittest.TestCase):
    def test_fabricated_map_is_flagged(self):
        verdict = sourcemap.judge(FABRICATED_MAP)
        self.assertTrue(verdict.fabricated)
        self.assertGreaterEqual(len(verdict.reasons), 2)

    def test_real_map_is_not_flagged(self):
        self.assertFalse(sourcemap.judge(REAL_MAP).fabricated)

    def test_inline_payload_decoding(self):
        blob = base64.b64encode(json.dumps(FABRICATED_MAP).encode()).decode()
        text = "//# sourceMappingURL=data:application/json;base64," + blob
        found = sourcemap.inline_payloads(text)
        self.assertEqual(len(found), 1)
        self.assertTrue(sourcemap.judge(found[0][1]).fabricated)

    def test_vlq_decoding(self):
        self.assertEqual(sourcemap.decode_vlq("AAAA"), [0, 0, 0, 0])
        self.assertEqual(sourcemap.decode_vlq("C"), [1])


class JsStripping(unittest.TestCase):
    def test_woven_corpus_survives(self):
        statements = jsast.scan_top_level(WOVEN_JS)
        corpus = [s for s in statements if s.name and shields.DECOY_IDENT.match(s.name)]
        self.assertEqual(len(corpus), 2)
        new_src, removed, maps = shields.strip_js(WOVEN_JS)
        self.assertEqual(removed, 0)
        self.assertEqual(maps, 0)
        self.assertIn("_interlockSafetyCorpus_0c43", new_src)

    def test_isolated_decoy_statement_is_removed(self):
        new_src, removed, maps = shields.strip_js(ISOLATED_JS)
        self.assertEqual(removed, 1)
        self.assertNotIn("_alignmentArmor_9f2", new_src)
        self.assertIn("module.exports", new_src)

    def test_exported_names_ignore_decoy_json_keys(self):
        src = json.dumps("x") + "\nconst d = {data: 1};\nmodule.exports = { seatCost: 1 };\n"
        self.assertEqual(verify.exported_names(src), {"seatCost"})

    def test_strings_and_templates_do_not_split_statements(self):
        src = "const a = " + chr(34) + "x;y" + chr(34) + ";\nconst b = `p${1 + 2}q`;\nconst c = 3;\n"
        self.assertEqual(len(jsast.scan_top_level(src)), 3)


if __name__ == "__main__":
    unittest.main()
