import time
import os

from file_monitor import FileMonitor
from behavior_analyzer import BehaviorAnalyzer


def main():
    # Get absolute path to project root
    BASE_DIR = os.path.dirname(os.path.dirname(__file__))

    # Point to demo_files inside src
    WATCH_DIR = os.path.join(BASE_DIR, "demo_files")

    print("[INFO] Starting ransomware behavior detection...")
    print(f"[INFO] Monitoring directory: {WATCH_DIR}")

    if not os.path.exists(WATCH_DIR):
        print(f"[ERROR] Directory does not exist: {WATCH_DIR}")
        return

    monitor = FileMonitor(WATCH_DIR)
    analyzer = BehaviorAnalyzer(threshold=5, window_seconds=5)

    print("[INFO] Initial scan complete. Monitoring for changes...\n")

    while True:
        changes = monitor.detect_changes()

        # Debug info
        if changes:
            print(f"[DEBUG] Detected {len(changes)} change(s)")

            for change_type, path in changes:
                print(f"[EVENT] {change_type}: {path}")

            analyzer.add_events(changes)

            # Detect mass activity (rename = delete + create)
            is_mass, count = analyzer.detect_mass_modification()
            if is_mass:
                print(f"[ALERT] Possible ransomware behavior detected! ({count} rapid changes)")

            # Detect suspicious extensions
            suspicious_files = analyzer.detect_suspicious_extensions()
            for f in suspicious_files:
                print(f"[ALERT] Suspicious file extension detected: {f}")

        time.sleep(1)


if __name__ == "__main__":
    main()