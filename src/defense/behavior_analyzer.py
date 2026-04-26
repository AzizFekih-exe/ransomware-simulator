import time
from collections import deque

class BehaviorAnalyzer:
    def __init__(self, threshold=10, window_seconds=5):
        self.events = deque()
        self.threshold = threshold
        self.window_seconds = window_seconds

    def add_events(self, changes):
        current_time = time.time()

        for change in changes:
            self.events.append((current_time, change))

        # Remove old events outside time window
        while self.events and (current_time - self.events[0][0] > self.window_seconds):
            self.events.popleft()

    def detect_mass_modification(self):
        modifications = [e for t, e in self.events if e[0] == "MODIFIED"]

        if len(modifications) >= self.threshold:
            return True, len(modifications)

        return False, len(modifications)

    def detect_suspicious_extensions(self, extensions=(".enc", ".locked", ".simulated")):
        flagged = []

        for _, event in self.events:
            _, path = event
            for ext in extensions:
                if path.endswith(ext):
                    flagged.append(path)

        return flagged