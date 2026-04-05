import argparse
import sys
import os

# Ensure the root dir is in PYTHON_PATH so 'runtime' and 'backend' imports work
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from runtime.engine.loop import SimulationLoop

def main():
    parser = argparse.ArgumentParser(description="Epidemic Simulation Runtime")
    parser.add_argument("--run-id", required=True, help="The UUID of the run")
    parser.add_argument("--topology", required=True, help="Topology type")
    
    args = parser.parse_args()
    
    loop = SimulationLoop(run_id=args.run_id, topology=args.topology)
    try:
        loop.run()
    except KeyboardInterrupt:
        print("Runtime terminated by backend.")

if __name__ == "__main__":
    main()
