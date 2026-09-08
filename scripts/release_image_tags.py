# SPDX-License-Identifier: Apache-2.0
"""Produce validated image-tag outputs for the GitHub release workflow."""
from __future__ import annotations

import argparse
import re


RELEASE_TAG = re.compile(
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)


def release_image_tags(tag: str) -> dict[str, list[str]]:
    if RELEASE_TAG.fullmatch(tag) is None or len(tag + "-optional") > 128 or tag.endswith("-optional"):
        raise ValueError("release tag must fit vX.Y.Z or vX.Y.Z-prerelease; the -optional suffix is reserved")
    image = "ghcr.io/brntech/lsdf"
    tags = {"runtime": [f"{image}:{tag}"], "optional": [f"{image}:{tag}-optional"]}
    if "-" not in tag:
        tags["runtime"].append(f"{image}:latest")
        tags["optional"].append(f"{image}:latest-optional")
    return tags


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    args = parser.parse_args(argv)
    try:
        tags = release_image_tags(args.tag)
    except ValueError as exc:
        parser.error(str(exc))
    for name, values in tags.items():
        print(f"{name}<<LSDF_IMAGE_TAGS")
        print("\n".join(values))
        print("LSDF_IMAGE_TAGS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
