# SPDX-License-Identifier: Apache-2.0
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from scripts.release_image_tags import main, release_image_tags


class ReleaseImageTagTests(unittest.TestCase):
    def test_stable_release_updates_both_latest_tags(self):
        tags = release_image_tags("v0.3.1")
        self.assertEqual(tags["runtime"], ["ghcr.io/brntech/lsdf:v0.3.1", "ghcr.io/brntech/lsdf:latest"])
        self.assertEqual(tags["optional"], ["ghcr.io/brntech/lsdf:v0.3.1-optional", "ghcr.io/brntech/lsdf:latest-optional"])

    def test_prereleases_never_change_latest(self):
        for tag in ("v0.3.1-rc.1", "v1.0.0-beta", "v2.0.0-alpha-2"):
            with self.subTest(tag=tag):
                tags = release_image_tags(tag)
                self.assertEqual(tags["runtime"], [f"ghcr.io/brntech/lsdf:{tag}"])
                self.assertEqual(tags["optional"], [f"ghcr.io/brntech/lsdf:{tag}-optional"])

    def test_invalid_or_injected_tags_are_rejected(self):
        for tag in ("v0.3.1-optional", "v0.3.1-rc.1-optional", "vmain", "0.3.1", "v01.3.1", "v1.2.3-", "v1.2.3+build", "v1.2.3\nlatest", "v1.2.3-" + "a" * 128):
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    release_image_tags(tag)

    def test_workflow_outputs_keep_prerelease_tags_separate(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(main(["v0.3.1-rc.1"]), 0)
        self.assertEqual(stdout.getvalue(),
            "runtime<<LSDF_IMAGE_TAGS\nghcr.io/brntech/lsdf:v0.3.1-rc.1\nLSDF_IMAGE_TAGS\n"
            "optional<<LSDF_IMAGE_TAGS\nghcr.io/brntech/lsdf:v0.3.1-rc.1-optional\nLSDF_IMAGE_TAGS\n")

    def test_invalid_tag_exits_before_writing_workflow_outputs(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                main(["vmain"])
        self.assertEqual(error.exception.code, 2)
        self.assertEqual(stdout.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
