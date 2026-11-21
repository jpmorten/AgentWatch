"""Fælles logging: konsol, logfil (~/.agentwatch/agentwatch.log) og en ringbuffer til GUI'en."""

from __future__ import annotations

import logging
import logging.handlers
import os
import threading
from collections import deque
from pathlib import Path

LOG = logging.getLogger("agentwatch")
LOG_FILE = Path(os.path.expanduser("~/.agentwatch/agentwatch.log"))
FMT = "%(asctime)s %(levelname)-7s %(message)s"


class RingBuffer(logging.Handler):
    """Holder de seneste linjer i hukommelsen, så GUI'en kan vise dem live."""

    def __init__(self, size: int = 1000):
        super().__init__(logging.INFO)
        self.lines: deque[tuple[int, str]] = deque(maxlen=size)
        self._seq = 0
        self._lock2 = threading.Lock()
        self.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:
            return
        if record.levelno >= logging.WARNING:
            msg = f"{msg}  [{record.levelname}]"
        with self._lock2:
            self._seq += 1
            self.lines.append((self._seq, msg))

    def since(self, seq: int = 0, limit: int = 500) -> tuple[int, list[str]]:
        with self._lock2:
            items = [(s, m) for s, m in self.lines if s > seq][-limit:]
            last = self.lines[-1][0] if self.lines else 0
        return last, [m for _, m in items]


BUFFER = RingBuffer()
_configured = False


def setup_logging(verbose: bool = False, console: bool = True) -> None:
    """Idempotent. verbose=True viser også DEBUG (fx nmap-kommandoer og rå nmap-output)."""
    global _configured
    LOG.setLevel(logging.DEBUG)
    LOG.propagate = False
    if not _configured:
        LOG.addHandler(BUFFER)
        try:
            LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter(FMT))
            LOG.addHandler(fh)
        except OSError:
            pass
        if console:
            ch = logging.StreamHandler()
            ch.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%H:%M:%S"))
            ch.set_name("console")
            LOG.addHandler(ch)
        for noisy in ("httpx", "httpcore", "zeroconf", "uvicorn.access"):
            logging.getLogger(noisy).setLevel(logging.WARNING)
        _configured = True
    for h in LOG.handlers:
        if h.get_name() == "console":
            h.setLevel(logging.DEBUG if verbose else logging.INFO)
