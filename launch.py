"""
Detection Engineering Platform — Full Launcher
Runs the complete pipeline for all 15 techniques, then opens the dashboard.

Usage:
    python launch.py
"""

import subprocess
import sys
import os

os.environ["PYTHONUTF8"] = "1"


def main():
    print("\n" + "=" * 60)
    print("  DETECTION ENGINEERING PLATFORM — FULL LAUNCH")
    print("=" * 60 + "\n")

    # Step 1: Run the full pipeline
    print("[1/2] Running pipeline for all 15 techniques...\n")
    result = subprocess.run([sys.executable, "run_all.py"], cwd=os.path.dirname(__file__) or ".")

    if result.returncode != 0:
        print("\n[!] Pipeline finished with errors. Launching dashboard anyway.\n")

    # Step 2: Launch the dashboard
    print("\n" + "=" * 60)
    print("[2/2] Launching Dashboard at http://localhost:8501 ...")
    print("      Press Ctrl+C to stop the dashboard.\n")

    try:
        subprocess.run([sys.executable, "-m", "streamlit", "run", "Dashboard/app.py"])
    except KeyboardInterrupt:
        print("\n\n  Dashboard stopped. Goodbye!\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Interrupted. Goodbye!\n")
