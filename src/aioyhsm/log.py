from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass, field
from hashlib import sha256
from struct import unpack

from .constants import Command


@dataclass(frozen=True)
class LogEntry:
    # First 16 bytes
    data: bytes = field(repr=False)

    # First 16 bytes, decoded
    command_number: int
    command_id: Union[int, Command]
    command_length: int
    session_key: int
    target_key0: int
    target_key1: int
    result: int
    systick: int

    # sha256(self.data + previous.digest)[:16]
    digest: bytes = field(repr=False)

    @classmethod
    def decode(cls, value: bytes) -> LogEntry:
        if len(value) != 32:
            raise ValueError(f"Bad length: {len(value)}")
        items = list(unpack(">HBHHHHBL16s", value))
        with suppress(ValueError):
            items[1] = Command(items[1])
        return cls(value[:16], *items)

    def verify(self, previous: LogEntry) -> bool:
        return sha256(self.data + previous.digest).digest()[:16] == self.digest
