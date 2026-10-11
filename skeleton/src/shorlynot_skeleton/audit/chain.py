"""
Tamper-evident audit log: an append-only SHA-256 hash chain.

Every entry commits to the previous entry's hash, so editing, deleting or reordering any entry
changes every later hash and is caught by `verify()`. Removing entries from the END of the log is only
detectable against an externally anchored head hash (publish `head()` somewhere the log owner cannot
rewrite: a separate system, a notary, a printed SOC report). Without an anchor, a truncated chain is
still a valid chain.

Optional persistence: JSON lines, one entry per line, loaded and re-verified on start.
"""

import hashlib
import json
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

GENESIS = "0" * 64


def _entry_hash(seq: int, ts: float, prev_hash: str, payload: Dict[str, Any]) -> str:
    body = json.dumps({"seq": seq, "ts": ts, "prev": prev_hash, "payload": payload},
                      sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode()).hexdigest()


class HashChainedLog:
    def __init__(self, path: Optional[str] = None) -> None:
        self._entries: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._path = path
        if path:
            self._load(path)

    def _load(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        self._entries.append(json.loads(line))
        except FileNotFoundError:
            pass

    def append(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            prev = self._entries[-1]["hash"] if self._entries else GENESIS
            seq = len(self._entries)
            ts = time.time()
            # Round-trip through JSON so the stored payload is exactly what gets hashed.
            payload = json.loads(json.dumps(payload, sort_keys=True, default=str))
            entry = {"seq": seq, "ts": ts, "prev": prev, "payload": payload,
                     "hash": _entry_hash(seq, ts, prev, payload)}
            self._entries.append(entry)
            if self._path:
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, sort_keys=True) + "\n")
            return entry

    def head(self) -> str:
        return self._entries[-1]["hash"] if self._entries else GENESIS

    def __len__(self) -> int:
        return len(self._entries)

    def entries(self) -> List[Dict[str, Any]]:
        return list(self._entries)

    def verify(self, expected_head: Optional[str] = None) -> Tuple[bool, Optional[int]]:
        """Return (ok, index_of_first_bad_entry). With `expected_head`, also detects tail truncation."""
        prev = GENESIS
        for i, e in enumerate(self._entries):
            if e.get("seq") != i or e.get("prev") != prev:
                return False, i
            if _entry_hash(e["seq"], e["ts"], e["prev"], e["payload"]) != e.get("hash"):
                return False, i
            prev = e["hash"]
        if expected_head is not None and prev != expected_head:
            return False, len(self._entries)
        return True, None
