#!/usr/bin/env python3
"""Trusted, executable release-policy decisions shared by build/GA/RC.

Never load policy thresholds or signing domains from an unsigned build artifact.
The legacy 0.36.0 format remains immutable. Every newer stable version uses a
new signature domain and its own exact-version/commit/byte-bound approval.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import re

_VERSION = re.compile(r'^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?$')

@dataclass(frozen=True)
class Policy:
    version: str
    ga_mode: str
    approval_schema: str
    execution_schema: str
    receipt_schema: str
    signing_domain: bytes
    receipt_name: str
    approval_name: str
    signature_name: str


def parsed(version: str):
    match = _VERSION.fullmatch(version)
    if not match or any(part.startswith('0') and len(part) > 1 for part in match.groups()[:3]):
        raise ValueError('invalid canonical release version: '+version)
    return tuple(int(p) for p in match.groups()[:3]), match.group(4)


def policy(version: str) -> Policy:
    number, prerelease = parsed(version)
    if number == (0, 36, 0) and prerelease is None:
        return Policy(version, 'legacy-ga036', 'neverlauncher.ga036.targets.v1',
                      'neverlauncher.ga036.execution.v1', 'neverlauncher.ga036.verified-targets.v1',
                      b'neverlauncher.ga036.targets.v1\x00', 'GA_VERIFIED_TARGETS_0360.json',
                      'GA_TARGET_APPROVAL_0360.json', 'GA_TARGET_APPROVAL_0360.sig')
    if number > (0, 36, 0):
        # Prerelease candidates must not impersonate a stable GA release.
        if prerelease is not None:
            raise ValueError('GA release policy refuses prerelease: '+version)
        return Policy(version, 'signed-ga-v2', 'neverlauncher.ga.targets.v2',
                      'neverlauncher.ga.execution.v2', 'neverlauncher.ga.verified-targets.v2',
                      b'neverlauncher.ga.targets.v2\x00', 'GA_VERIFIED_TARGETS.json',
                      'GA_TARGET_APPROVAL.json', 'GA_TARGET_APPROVAL.sig')
    return Policy(version, 'historical', '', '', '', b'', '', '', '')


def rc_extended(version: str) -> bool:
    number, _ = parsed(version)
    return number >= (0, 35, 14)


def rc_supported(version: str) -> bool:
    number, _ = parsed(version)
    return number in ((0, 32, 16), (0, 33, 0)) or rc_extended(version)


def legacy_admin_supported(version: str) -> bool:
    number, _ = parsed(version)
    return number >= (0, 22, 0)


def legacy_profiles_supported(version: str) -> bool:
    number, _ = parsed(version)
    return number >= (0, 23, 0)


def requires_rehearsal(version: str) -> bool:
    number, prerelease = parsed(version)
    return prerelease is None and number >= (0, 36, 5)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('ga-mode', 'rc-extended', 'rc-supported', 'requires-rehearsal'))
    p.add_argument('--version', required=True)
    args = p.parse_args()
    try:
        result = policy(args.version).ga_mode if args.action == 'ga-mode' else ('1' if
            (rc_extended(args.version) if args.action == 'rc-extended' else
             rc_supported(args.version) if args.action == 'rc-supported' else
             requires_rehearsal(args.version)) else '0')
    except ValueError as exc:
        p.error(str(exc))
    print(result)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
