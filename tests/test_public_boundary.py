import json
import re
import unittest
from pathlib import Path


PUBLIC_TEXT_ROOTS = [
    Path("README.md"),
    Path("CHANGELOG.md"),
    Path("CONTRIBUTING.md"),
    Path("EVAL.md"),
    Path("SECURITY.md"),
    Path("LICENSE"),
    Path(".dockerignore"),
    Path(".gitignore"),
    Path("Dockerfile"),
    Path("docker-compose.yml"),
    Path("compose.release.yaml"),
    Path("release.env.example"),
    Path("pyproject.toml"),
    Path("docs"),
    Path("evals"),
    Path("examples"),
    Path("policies"),
    Path("scripts"),
    Path("src"),
    Path("tests"),
]

FORBIDDEN_PUBLIC_TERMS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bPiece\s*[ABC]\b",
        r"\bpiece\s*[abc]\b",
        # Reject internal tracker labels without publishing private project
        # names or examples. Check legitimate technical notation before
        # narrowing this generic boundary pattern.
        r"\bP\d+\.(?:[A-Z]\.\d+|[A-Z]|\d+)\b",
        r"\bPaper\s+A/?B\b",
        r"\bPaper\s+[ABC]\b",
        r"\bPhase\s*\d",
        r"\bphase\s*\d",
        r"\bphase\d",
        r"private benchmark",
        r"benchmark history",
        r"memory/",
        r"overnight",
        r"sausage",
        r"you and I",
        r"current plan",
        r"alignment check",
        r"first-choice backlog",
        r"experiment inside",
    )
] + [
    re.compile(r"\bPiece-[ABC]\b"),
]

REAL_SECRET_PATTERNS = [
    re.compile(r"OPENROUTER_API_KEY\s*=\s*sk", re.IGNORECASE),
    re.compile(r"LSDF_UPSTREAM_API_KEY\s*=\s*sk", re.IGNORECASE),
    re.compile(r"api[_-]?key\s*[:=]\s*sk", re.IGNORECASE),
]

SAMPLE_OUTPUT_ROOTS = [
    Path("docs/artifacts/optional-detectors"),
    Path("examples/proof-bundle-sample"),
    Path("examples/quickstart/audit.jsonl"),
]

RAW_DEMO_VALUES = [
    "api_LSDF_FIXTURE_TOKEN_000000",
    "000-00-0000",
    "LSDF-FIXTURE-00001",
]


class PublicRepoBoundaryTests(unittest.TestCase):
    def test_readme_leads_with_local_agent_quickstart(self):
        top = "\n".join(Path("README.md").read_text(encoding="utf-8").splitlines()[:40])

        self.assertIn("local LLM agents", top)
        self.assertIn("docker compose --profile demo up", top)
        self.assertIn("docker compose run --rm cli init --upstream lmstudio", top)
        self.assertIn("http://localhost:8080/v1", top)

    def test_public_docs_examples_and_release_surfaces_omit_internal_terms(self):
        for path in _public_text_files():
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                for pattern in FORBIDDEN_PUBLIC_TERMS:
                    self.assertIsNone(pattern.search(text), pattern.pattern)

    def test_public_boundary_scan_includes_foundation_fixtures(self):
        public_paths = {path.as_posix() for path in _public_text_files()}

        self.assertTrue(
            any(
                path.startswith("tests/foundation/fixtures/")
                and path.endswith(".json")
                for path in public_paths
            ),
            "foundation fixture JSON files must stay inside the public boundary scan",
        )

    def test_public_docs_and_examples_do_not_include_real_provider_keys(self):
        for path in _public_text_files():
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                for pattern in REAL_SECRET_PATTERNS:
                    self.assertIsNone(pattern.search(text), pattern.pattern)

    def test_sample_outputs_are_raw_value_safe(self):
        for path in _sample_output_files():
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                for raw in RAW_DEMO_VALUES:
                    self.assertNotIn(raw, text)
                if path.suffix == ".json":
                    json.loads(text)
                elif path.suffix == ".jsonl":
                    for line in text.splitlines():
                        if line.strip():
                            json.loads(line)


def _public_text_files():
    for root in PUBLIC_TEXT_ROOTS:
        if root.is_file():
            yield root
            continue
        for path in root.rglob("*"):
            if path == Path("tests/test_public_boundary.py"):
                continue
            if path.is_file() and path.suffix.lower() in {".md", ".txt", ".json", ".jsonl", ".env", ".yaml", ".yml", ".js", ".py", ".sh", ".toml"}:
                yield path


def _sample_output_files():
    for root in SAMPLE_OUTPUT_ROOTS:
        if root.is_file():
            yield root
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".md", ".json", ".jsonl"}:
                yield path


if __name__ == "__main__":
    unittest.main()
