"""Event bus — lets modules emit structured events that the GUI (and any
future subscribers) can observe in real time.

Zero-dependency: built on stdlib queue.Queue + threading.Lock. Modules that
don't care about events pay zero cost (emit() is O(n_subscribers); when
there are no subscribers, it's a single Lock acquire + for-loop over empty).

Usage from inside a module:
    from .events import bus
    bus.emit("discovery.host_found", {"ip": "10.0.0.50", "services": [...]})

Usage from a subscriber (GUI server, test harness):
    q = bus.subscribe()
    while True:
        event = q.get()
        # do something with event
"""
from __future__ import annotations

import threading
import time
from queue import Queue, Full


class EventBus:
    def __init__(self, queue_size: int = 2048):
        self._subscribers: list[Queue] = []
        self._lock = threading.Lock()
        self._queue_size = queue_size
        self._all_events: list[dict] = []       # retained history
        self._history_cap = 10_000

    def emit(self, event_type: str, data: dict | None = None) -> None:
        event = {
            "type": event_type,
            "data": data or {},
            "timestamp": time.time(),
        }
        with self._lock:
            # History so late subscribers can replay
            self._all_events.append(event)
            if len(self._all_events) > self._history_cap:
                # Drop oldest 10 % when we hit the cap
                drop = self._history_cap // 10
                self._all_events = self._all_events[drop:]
            for q in list(self._subscribers):
                try:
                    q.put_nowait(event)
                except Full:
                    # Subscriber is lagging; drop this event for them
                    pass

    def subscribe(self, replay_history: bool = True) -> Queue:
        q: Queue = Queue(maxsize=self._queue_size)
        with self._lock:
            if replay_history:
                for ev in self._all_events:
                    try:
                        q.put_nowait(ev)
                    except Full:
                        break
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def clear_history(self) -> None:
        with self._lock:
            self._all_events.clear()


# Module-level singleton. Import via `from modules.events import bus`.
bus = EventBus()


# ---- Convenience emitters so modules don't need to remember event names ----

def phase(name: str, detail: str = "") -> None:
    bus.emit("phase", {"name": name, "detail": detail})


def log(level: str, msg: str) -> None:
    bus.emit("log", {"level": level, "msg": msg})


def finding(severity: str, host: str, title: str, detail: str = "") -> None:
    bus.emit("finding", {"severity": severity, "host": host,
                         "title": title, "detail": detail})
