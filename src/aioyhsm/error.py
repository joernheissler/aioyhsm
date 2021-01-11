from __future__ import annotations

from .constants import Error


class YubiHsmError(Exception):
    def __init__(self, code: Error) -> None:
        self.code = code
