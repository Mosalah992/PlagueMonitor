import subprocess
import os
import sys

# Maintain a mapping of run_id to subprocess.Popen objects
_active_runs = {}

def start_runtime_process(run_id: str, topology: str):
    if run_id in _active_runs:
        return False
    
    # Path to the runtime script in the local monorepo
    runtime_script = os.path.join(os.path.dirname(__file__), "..", "..", "..", "runtime", "main.py")
    runtime_script = os.path.abspath(runtime_script)
    
    cmd = [
        sys.executable, 
        runtime_script,
        "--run-id", run_id,
        "--topology", topology
    ]
    
    # Spawn background process
    proc = subprocess.Popen(cmd)
    _active_runs[run_id] = proc
    return True

def stop_runtime_process(run_id: str):
    proc = _active_runs.get(run_id)
    if proc:
        proc.terminate()
        proc.wait(timeout=5)
        del _active_runs[run_id]
        return True
    return False

def is_running(run_id: str) -> bool:
    proc = _active_runs.get(run_id)
    if proc:
        if proc.poll() is None:
            return True
        else:
            del _active_runs[run_id]
            return False
    return False
