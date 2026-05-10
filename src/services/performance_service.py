import time
import psutil


class PerformanceTracker:
    def __init__(self):
        self.process = psutil.Process()
        self.start_time = None
        self.start_memory = None

    def start(self):
        self.start_time = time.perf_counter()
        self.start_memory = self.process.memory_info().rss

    def stop(self):
        end_time = time.perf_counter()
        end_memory = self.process.memory_info().rss

        exec_ms = (end_time - self.start_time) * 1000
        mem_kb = abs(end_memory - self.start_memory) / 1024

        return exec_ms, mem_kb