import unittest
from pathlib import Path


class OpenSourceHygieneTests(unittest.TestCase):
    def test_contributing_documents_required_workflow(self):
        text = Path("CONTRIBUTING.md").read_text(encoding="utf-8")

        for required in (
            "## Pull Request Process",
            "## Test Expectations",
            "docker compose run --rm test",
            "## DCO Sign-Off",
            "git commit -s",
            "Signed-off-by:",
            "## Licensing",
            "Apache-2.0",
            "## Code Style",
            "raw-value-safe defaults",
            "## Sensitive Data Warning",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)

    def test_lsdf_source_files_have_apache_spdx_header(self):
        license_text = Path("LICENSE").read_text(encoding="utf-8")
        self.assertTrue(license_text.lstrip().startswith("Apache License"))
        self.assertIn("Version 2.0, January 2004", license_text)
        # Prevent accidentally shipping another shortened license.
        import hashlib
        normalized = license_text.replace("\r\n", "\n").encode("utf-8")
        self.assertEqual(hashlib.sha256(normalized).hexdigest(),
                         "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30")

        expected = "# SPDX-License-Identifier: Apache-2.0"
        source_files = sorted(Path("src/lsdf").rglob("*.py"))
        self.assertGreater(len(source_files), 0)
        for path in source_files:
            with self.subTest(path=str(path)):
                first_line = path.read_text(encoding="utf-8").splitlines()[0]
                self.assertEqual(first_line, expected)

    def test_third_party_notices_cover_bundled_external_corpus(self):
        notices = Path("THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        for required in (
            "guardion/BR-Agentic-PII-Benchmark",
            "evals/br_agentic_pii.json",
            "https://huggingface.co/datasets/guardion/BR-Agentic-PII-Benchmark",
            "License: MIT",
            "MIT License",
            "Permission is hereby granted",
        ):
            with self.subTest(required=required):
                self.assertIn(required, notices)


if __name__ == "__main__":
    unittest.main()
