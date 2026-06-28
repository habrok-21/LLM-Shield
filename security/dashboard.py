"""
ShieldLLM — Live Security Dashboard (SSE Stream).

Provides a real-time Server-Sent Events (SSE) endpoint that streams
security events to connected clients (ops dashboards, SIEMs, or
browser-based monitoring tools).

Events are JSON-formatted and identical to the audit log format.

Usage:
    GET /events  →  SSE stream of ShieldLLM security events
"""

import asyncio
import json
import logging
from typing import Any, Dict, List

from .state import stats

logger = logging.getLogger("shieldllm.dashboard")


class EventBus:
    """Simple in-memory pub/sub for security events.

    Subscribers receive every event as a JSON string via an asyncio
    Queue. Events older than the retention window are discarded.
    """

    def __init__(self, max_subscribers: int = 50, retention: int = 1000):
        self._subscribers: List[asyncio.Queue] = []
        self._max_subscribers = max_subscribers
        self._retention = retention
        self._ring: List[Dict[str, Any]] = []
        self._ring_index = 0

    def publish(self, event: Dict[str, Any]) -> None:
        """Broadcast an event to all connected subscribers."""
        stats.push_event(event)
        if len(self._ring) < self._retention:
            self._ring.append(event)
        else:
            self._ring[self._ring_index] = event
            self._ring_index = (self._ring_index + 1) % self._retention

        # Push to all subscribers
        payload = json.dumps(event, default=str)
        dead = []
        for q in self._subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self._subscribers.remove(q)

    def subscribe(self) -> asyncio.Queue:
        """Register a new subscriber. Returns an asyncio.Queue."""
        if len(self._subscribers) >= self._max_subscribers:
            raise RuntimeError("max subscribers reached")
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._subscribers.append(q)
        logger.debug("dashboard_subscriber_added total=%d", len(self._subscribers))
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """Remove a subscriber."""
        if q in self._subscribers:
            self._subscribers.remove(q)
            logger.debug("dashboard_subscriber_removed total=%d", len(self._subscribers))

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


# Singleton event bus
event_bus = EventBus()


async def event_generator() -> str:
    """Async generator for SSE events."""
    q = event_bus.subscribe()
    try:
        # Send initial keepalive
        yield f"data: {json.dumps({'shieldllm_event': 'CONNECTED', 'message': 'ShieldLLM dashboard connected'})}\n\n"
        while True:
            try:
                payload = await asyncio.wait_for(q.get(), timeout=30.0)
                yield f"data: {payload}\n\n"
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"  # SSE comment (keepalive)
    except asyncio.CancelledError:
        pass
    finally:
        event_bus.unsubscribe(q)
