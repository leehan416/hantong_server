from collections import deque


class SlidingLimit:
    """Per-key sliding window kept in memory; valid only for a single process."""

    def __init__(self, limit: int, window: float = 60, capacity: int = 1000) -> None:
        self.limit = limit
        self.window = window
        self.capacity = capacity
        self.buckets: dict[str, deque[float]] = {}

    def allow(self, key: str, now: float) -> bool:
        bucket = self.buckets.get(key)
        if bucket is None:
            if len(self.buckets) >= self.capacity:
                self._evict_idle(now)
            if len(self.buckets) >= self.capacity:
                if not self.buckets:
                    return False
                oldest = min(self.buckets, key=lambda item: self.buckets[item][-1])
                del self.buckets[oldest]
            bucket = deque()
            self.buckets[key] = bucket
        self._expire(bucket, now)
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True

    def _expire(self, bucket: deque[float], now: float) -> None:
        while bucket and bucket[0] <= now - self.window:
            bucket.popleft()

    def _evict_idle(self, now: float) -> None:
        for key, bucket in list(self.buckets.items()):
            self._expire(bucket, now)
            if not bucket:
                del self.buckets[key]
