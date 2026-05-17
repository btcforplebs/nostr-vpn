#!/usr/bin/env python3
"""Compatibility wrapper for the canonical TestFlight internal shipper.

The old implementation attached whichever App Store Connect build sorted as
"latest". During release uploads that can still be the previous build while
Apple indexes the new IPA, so keep this entry point but delegate to
scripts/testflight-internal, which waits for the exact workspace build number.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    legacy_group = env.get("NVPN_TESTFLIGHT_INTERNAL_GROUP", "").strip()
    if legacy_group and not env.get("NVPN_TESTFLIGHT_GROUPS", "").strip():
        env["NVPN_TESTFLIGHT_GROUPS"] = legacy_group
    return subprocess.call(
        [str(root / "scripts" / "testflight-internal"), "put"],
        env=env,
    )


if __name__ == "__main__":
    raise SystemExit(main())
