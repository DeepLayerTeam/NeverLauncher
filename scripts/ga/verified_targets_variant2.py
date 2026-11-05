#!/usr/bin/env python3
"""Обратно совместимая точка входа верификатора 0.36.0 (формат подписи без изменений)."""
from verified_targets import *  # noqa: F401,F403: historical public imports
from verified_targets import main

if __name__ == '__main__':
    raise SystemExit(main())
