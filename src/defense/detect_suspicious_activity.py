import time
from file_monitor import FileMonitor
from behavior_analyzer import BehaviorAnalyzer

WATCH_DIR = "demo_files"  # change if needed

def main():
    monitor = FileMonitor(WATCH_DIR)
    analyzer = BehaviorAnalyzer(threshold=8, window_seconds=5)

    print("[INFO] Starting ransomware behavior detection...")
    print(f"[INFO] Monitoring directory: {WATCH_DIR}")

    while True:
        changes = monitor.detect_changes()

        if changes:
            for change_type, path in changes:
                print(f"[EVENT] {change_type}: {path}")

            analyzer.add_events(changes)

            # Detect mass modification
            is_mass, count = analyzer.detect_mass_modification()
            if is_mass:
                print(f"[ALERT] Possible ransomware behavior detected! ({count} rapid modifications)")

            # Detect suspicious extensions
            suspicious_files = analyzer.detect_suspicious_extensions()
            for f in suspicious_files:
                print(f"[ALERT] Suspicious file extension detected: {f}")

        time.sleep(1)

if __name__ == "__main__":
    main()