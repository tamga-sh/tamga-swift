#!/usr/bin/env python3
"""Scripts/ci-use-local-xcframework.py

Swaps Package.swift's committed `TamgaCore` binaryTarget from its
`url:`/`checksum:` form (pointing at this repo's own release assets, which
don't exist yet -- see CLAUDE.md's "Local Development" section) to the
`path:` form, pointed at a locally built XCFramework. Used only in CI
(.github/workflows/ci.yml's macOS and iOS jobs each build a real
TamgaCore.xcframework from tamga-c's own already-published releases before
calling this) so `swift test`/`xcodebuild test` can actually resolve and
run against real code instead of failing on the unresolvable placeholder
URL. The checkout is fresh on every CI run, so this is never committed --
same as the manual swap a human contributor makes locally per CLAUDE.md,
just automated.

Usage: python3 Scripts/ci-use-local-xcframework.py <path-relative-to-package-root>

The path MUST be relative to the package root (where Package.swift lives),
not absolute -- SwiftPM's binaryTarget(path:) rejects absolute paths
outright ("path expected to be relative to package root"), confirmed
directly against a real `swift build` before this script settled on that
requirement.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

BINARY_TARGET_PATTERN = re.compile(
    r'\.binaryTarget\(\s*name:\s*"TamgaCore".*?\),', re.DOTALL
)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <path-relative-to-package-root>", file=sys.stderr)
        return 2
    xcframework_path = sys.argv[1]
    if Path(xcframework_path).is_absolute():
        print(
            f"error: SwiftPM binaryTarget(path:) requires a path relative to "
            f"the package root, got an absolute path: {xcframework_path!r}",
            file=sys.stderr,
        )
        return 2

    manifest_path = Path("Package.swift")
    content = manifest_path.read_text()

    replacement = (
        ".binaryTarget(\n"
        '            name: "TamgaCore",\n'
        f'            path: "{xcframework_path}"\n'
        "        ),"
    )
    new_content, count = BINARY_TARGET_PATTERN.subn(replacement, content, count=1)
    if count != 1:
        print(
            f"error: expected exactly 1 TamgaCore binaryTarget block in "
            f"Package.swift, found {count} -- refusing to guess",
            file=sys.stderr,
        )
        return 1

    manifest_path.write_text(new_content)
    print(f"Package.swift now points TamgaCore at: {xcframework_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
