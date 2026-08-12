#!/usr/bin/env python3
"""Scripts/find-ios-simulator.py

Prints the id and name of the first concrete (non-placeholder) iPhone
Simulator destination for the Tamga-Package scheme, reading `xcodebuild
-scheme Tamga-Package -showdestinations` output (plain text -- xcodebuild has
no JSON mode for -showdestinations) from stdin.

Why xcodebuild's own destination list, and not `simctl list devices
available`: an earlier version of this script queried simctl directly and
picked a device by name (e.g. "iPhone 16 Pro"). Confirmed directly (tamga-sh/
tamga-swift CI run 31622776739) that simctl reported that device as
available, yet `xcodebuild -destination "platform=iOS Simulator,name=iPhone
16 Pro"` under that same job's Xcode 16.1 rejected it -- the device wasn't
even listed as "ineligible", just entirely absent from xcodebuild's own
destination list. A local reproduction with the identical Package.swift and
XCFramework, run against a different Xcode install, listed dozens of concrete
iOS Simulator destinations without issue -- confirming the XCFramework/
Package.swift were never the problem. GitHub's macOS runner images carry
simulator devices and runtimes spanning multiple co-installed Xcode
versions; simctl's device registry is not scoped to whichever Xcode is
selected via DEVELOPER_DIR, but xcodebuild's own destination resolution is.
Asking `xcodebuild -showdestinations` directly -- the exact same command
about to run the test -- is the only way to know what IT considers valid,
instead of what some other, possibly Xcode-version-incompatible simulator
runtime happens to be registered on the machine.

Matches by `id:` (a stable per-instance UUID) rather than `name:` -- avoids a
second, unrelated ambiguity where more than one installed runtime can
register a device under the same model name, and an unqualified name match
could silently resolve to the wrong OS version.

Usage:
  xcodebuild -scheme Tamga-Package -showdestinations 2>&1 | python3 Scripts/find-ios-simulator.py
Prints two lines to stdout on success: the destination id, then its name.
Exits 1 (no output) if no concrete iPhone Simulator destination is found.
"""

from __future__ import annotations

import re
import sys

# e.g. "  { platform:iOS Simulator, arch:x86_64, id:E10D30DF-..., OS:26.5, name:iPhone 17 }"
DESTINATION_RE = re.compile(r"platform:iOS Simulator.*?\bid:([0-9A-Fa-f-]+).*?\bname:([^,}]+)")


def main() -> int:
    for line in sys.stdin:
        if "platform:iOS Simulator" not in line or "placeholder" in line or "iPhone" not in line:
            continue
        match = DESTINATION_RE.search(line)
        if not match:
            continue
        device_id, name = match.group(1), match.group(2).strip()
        print(device_id)
        print(name)
        return 0
    print(
        "error: no concrete iPhone Simulator destination found in "
        "xcodebuild -showdestinations output",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
