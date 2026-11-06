#!/usr/bin/env python3
"""Проверяет разбор свидетельств сертификации, включая опасный случай пропущенного теста."""
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
        raise AssertionError("Небезопасное свидетельство GA было принято")
print("Проверка свидетельств GA: PASS (пропущенные, отсутствующие и упавшие тесты отклонены)")

# Последующий PASS никогда не должен стирать предыдущий FAIL или SKIP для
# того же теста.
for bad in (event('TestA', 'fail')+'\n'+event('TestA','pass'),
            event('TestA','skip')+'\n'+event('TestA','pass')):
    try:
        mod.validate_test_events(bad, ('TestA',))
    except ValueError:
        pass
    else:
        raise AssertionError('GA принял пропущенную или проваленную предшествующую проверку')
