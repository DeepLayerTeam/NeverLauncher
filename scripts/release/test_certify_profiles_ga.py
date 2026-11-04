#!/usr/bin/env python3
"""Exercise certification evidence parsing, including the dangerous skipped-test case."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import importlib.util

spec = importlib.util.spec_from_file_location("profiles_ga", Path(__file__).with_name("certify-profiles-ga-0230.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def event(test, action):
    return json.dumps({"Test": test, "Action": action})


mod.validate_test_events(event("TestA", "run") + "\n" + event("TestA", "pass"), ("TestA",))
for bad in (event("TestA", "skip"), event("TestOther", "pass"), event("TestA", "fail")):
    try:
        mod.validate_test_events(bad, ("TestA",))
    except ValueError:
        pass
    else:
        raise AssertionError("unsafe GA evidence accepted")
print("GA evidence validation: PASS (skipped/missing/failed tests rejected)")

# A later PASS must never erase a prior FAIL or SKIP for the same test.
for bad in (event('TestA', 'fail')+'\n'+event('TestA','pass'),
            event('TestA','skip')+'\n'+event('TestA','pass')):
    try:
        mod.validate_test_events(bad, ('TestA',))
    except ValueError:
        pass
    else:
        raise AssertionError('GA accepted a skipped/failed preceding test')
