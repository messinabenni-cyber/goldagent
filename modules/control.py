"""Runtime control primitives — lets the GUI (or any controller) signal
in-flight scans and calls to stop cleanly.

Two threading.Events exposed through a singleton:
  - scan_cancel  → set to abort the whole scan at the next safe point
  - call_hangup  → set to end the current live call (equivalent to pressing
                   End on your mobile)

Modules that want to be cancellable import `controller` and check these
events inside their main loops. Default = cleared, so CLI usage is
unaffected.
"""
from __future__ import annotations

import threading


class Controller:
    def __init__(self) -> None:
        self.scan_cancel = threading.Event()
        self.call_hangup = threading.Event()

    def reset(self) -> None:
        self.scan_cancel.clear()
        self.call_hangup.clear()


controller = Controller()
