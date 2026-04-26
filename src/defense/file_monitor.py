import os
import time


class FileMonitor:
    def __init__(self, target_dir):
        self.target_dir = target_dir
        self.file_snapshot = self.scan_files()  # ✅ critical fix

    def scan_files(self):
        current_snapshot = {}

        for root, _, files in os.walk(self.target_dir):
            for f in files:
                path = os.path.join(root, f)
                try:
                    current_snapshot[path] = os.path.getmtime(path)
                except:
                    continue

        return current_snapshot

    def detect_changes(self):
        new_snapshot = self.scan_files()
        changes = []

        # Detect new or modified files
        for path, mtime in new_snapshot.items():
            if path not in self.file_snapshot:
                changes.append(("CREATED", path))
            elif self.file_snapshot[path] != mtime:
                changes.append(("MODIFIED", path))

        # Detect deleted files
        for path in self.file_snapshot:
            if path not in new_snapshot:
                changes.append(("DELETED", path))

        self.file_snapshot = new_snapshot
        return changes