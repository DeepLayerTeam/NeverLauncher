"""Portable isolated process trees. Never kill an unrelated process group."""
import os
import signal
import subprocess
import sys


def group_flags():
    if sys.platform=='win32':
        return {'creationflags':subprocess.CREATE_NEW_PROCESS_GROUP}
    return {'start_new_session':True}


def kill_tree(proc):
    if proc.poll() is not None:return
    if sys.platform=='win32':
        subprocess.run(['taskkill','/T','/F','/PID',str(proc.pid)],stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15,check=False)
    else:
        try:os.killpg(proc.pid,signal.SIGKILL)
        except ProcessLookupError:pass


def stop_tree(proc):
    if proc.poll() is not None:return
    if sys.platform=='win32':
        kill_tree(proc)
    else:
        try:os.killpg(proc.pid,signal.SIGTERM)
        except ProcessLookupError:pass
