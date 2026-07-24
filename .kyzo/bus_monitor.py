#!/usr/bin/env python3
"""Durable Claude→Cursor unread watcher.

Writes `.kyzo/bus-unread.json` when tips exist after the consume arm.
Never advances the arm — only `mailbox.py read` consumes.

Log line `BUS_UNREAD` is edge-triggered: printed only when the unread id
set changes. Polling the same tip every 3s must not spam follow-up hooks.
"""
from __future__ import annotations

import importlib.util
import os
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PID = ROOT / "bus-monitor.pid"
POLL_S = 3.0


def _load_mailbox():
    path = ROOT / "mailbox.py"
    spec = importlib.util.spec_from_file_location("kyzo_mailbox", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> None:
    mb = _load_mailbox()
    PID.write_text(f"{os.getpid()}\n")
    print(f"BUS_MONITOR armed_after={mb.read_arm()} pid={os.getpid()}", flush=True)
    last_ids: tuple[int, ...] | None = None
    try:
        while True:
            try:
                tips = mb.claude_to_cursor(mb.read_arm())
                ids = tuple(sorted(int(t["id"]) for t in tips))
                if tips:
                    mb.write_unread(tips)
                    if ids != last_ids:
                        print(
                            f"BUS_UNREAD count={len(tips)} ids={list(ids)}",
                            flush=True,
                        )
                        last_ids = ids
                else:
                    mb.clear_unread()
                    if last_ids is not None:
                        print("BUS_CLEAR", flush=True)
                        last_ids = None
            except (OSError, TimeoutError, RuntimeError, ValueError) as e:
                print(f"BUS_MONITOR_ERR {e}", flush=True)
            time.sleep(POLL_S)
    finally:
        if PID.exists() and PID.read_text().strip() == str(os.getpid()):
            PID.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
