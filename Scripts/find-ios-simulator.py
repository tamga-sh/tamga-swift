#!/usr/bin/env python3
"""Scripts/find-ios-simulator.py

Prints the name of the first available iPhone simulator on an iOS runtime,
reading `xcrun simctl list devices available --json` from stdin. Used by
.github/workflows/ci.yml's iOS job instead of a hardcoded device name (e.g.
"iPhone 16") -- which simulator runtimes/devices are pre-installed varies by
runner image and Xcode version; confirmed directly that one real CI runner
(macos-15 + Xcode 16.1 selected via maxim-lobanov/setup-xcode) had no
concrete iOS Simulator device available at all under that name, only the
"Any iOS Simulator Device" placeholder.

Usage: xcrun simctl list devices available --json | python3 Scripts/find-ios-simulator.py
Exits 1 (no output) if no available iPhone simulator is found on any iOS runtime.
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    data = json.load(sys.stdin)
    for runtime, devices in data["devices"].items():
        if "iOS" not in runtime:
            continue
        for device in devices:
            if device["isAvailable"] and "iPhone" in device["name"]:
                print(device["name"])
                return 0
    print("error: no available iPhone simulator found on any iOS runtime", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
