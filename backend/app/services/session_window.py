"""Small bounded session window for detecting attacks split across chat turns."""
from collections import defaultdict, deque
from threading import Lock
from time import monotonic


class SessionWindow:
    def __init__(self, max_messages: int = 6, ttl_seconds: int = 1800):
        self.max_messages = max_messages
        self.ttl_seconds = ttl_seconds
        self._items: dict[str, deque[tuple[float, str]]] = defaultdict(
            lambda: deque(maxlen=max_messages)
        )
        self._lock = Lock()

    def add_and_join(self, session_id: str, message: str) -> str:
        now = monotonic()
        with self._lock:
            window = self._items[session_id]
            while window and now - window[0][0] > self.ttl_seconds:
                window.popleft()
            window.append((now, message))
            return "\n".join(value for _, value in window)

    def get_history(self, session_id: str) -> list[str]:
        with self._lock:
            return [value for _, value in self._items.get(session_id, [])]

    def clear(self, session_id: str):
        with self._lock:
            if session_id in self._items:
                del self._items[session_id]


session_windows = SessionWindow()

