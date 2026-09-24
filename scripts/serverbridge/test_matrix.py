#!/usr/bin/env python3
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("sb_matrix", ROOT / "scripts/serverbridge/matrix.py")
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
data = module.load(ROOT / "serverbridge/targets.json")
assert len(data["targets"]) == 11
assert sum(1 for x in data["targets"] if x["role"] == "proxy") == 3
assert sum(1 for x in data["targets"] if x["role"] == "backend") == 8
assert next(x for x in data["targets"] if x["id"] == "bukkit")["coverage"] == "build-compatibility"
print("ServerBridge matrix tests OK")
