from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

from py_analyzer import scan_file


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = PROJECT_ROOT.parents[1]
DEFAULT_SLICES_ROOT = WORKSPACE_ROOT / "specification-master" / "specification-master" / "slices"
SLICES_ROOT = Path(os.getenv("SPECIFICATION_SLICES_ROOT", str(DEFAULT_SLICES_ROOT)))


class SpecificationSliceTests(unittest.TestCase):
    def test_analyzer_matches_official_specification_outputs(self) -> None:
        if not SLICES_ROOT.exists():
            self.skipTest(
                "Official specification slices were not found. Set SPECIFICATION_SLICES_ROOT "
                "to run this regression test outside the original workspace."
            )

        cases = sorted(SLICES_ROOT.glob("*/*.py"))
        self.assertGreater(len(cases), 0, f"No specification slices found under {SLICES_ROOT}")

        for slice_path in cases:
            with self.subTest(slice=slice_path.relative_to(SLICES_ROOT)):
                stem = slice_path.with_suffix("")
                patterns_path = stem.with_suffix(".patterns.json")
                expected_path = stem.with_suffix(".output.json")

                self.assertTrue(patterns_path.exists(), f"Missing patterns file: {patterns_path}")
                self.assertTrue(expected_path.exists(), f"Missing expected output file: {expected_path}")

                actual = scan_file(str(slice_path), str(patterns_path))
                expected = json.loads(expected_path.read_text(encoding="utf-8"))

                self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
