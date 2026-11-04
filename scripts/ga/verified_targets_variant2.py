#!/usr/bin/env python3
"""Backwards-compatible 0.36.0 verifier entry point (unchanged signed format)."""
from verified_targets import *  # noqa: F401,F403: historical public imports
from verified_targets import main

if __name__ == '__main__':
    raise SystemExit(main())
