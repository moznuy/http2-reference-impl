from __future__ import annotations

import dataclasses


@dataclasses.dataclass(slots=True, kw_only=True, frozen=True)
class Header:
    key: str
    value: str | None


# TODO:    Indices strictly greater than the sum of the lengths of both tables
#    MUST be treated as a decoding error.

STATIC_TABLE: list[Header | None] = [
    None,
    Header(key=":authority", value=None),
    Header(key=":method", value=None),
    Header(key=":method", value=None),
    Header(key=":path", value=None),
    Header(key=":path", value=None),
    Header(key=":scheme", value=None),
    Header(key=":scheme", value=None),
    Header(key=":status", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
    Header(key="", value=None),
]


class HPack:
    def __init__(self):
        self.result: list[Header] = []
        self.static_table = []
        # TODO: To limit the
        #    memory requirements of the decoder, the dynamic table size is
        #    strictly bounded (see Section 4.2).
        self.dynamic_table = []

    def add(self, data: bytes):
        pass

    def finalize(self) -> dict[str, list[str]]:
        return self.result
