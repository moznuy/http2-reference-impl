from __future__ import annotations

import dataclasses
import enum
from collections.abc import Mapping

from http2 import hpack


def default_settings() -> Settings:
    # TODO: fill default settings
    return Settings()


def default_streams() -> dict[int, Stream]:
    return {0: Stream(identifier=0)}


def default_decoder() -> hpack.HPack:
    return hpack.HPack(max_table_size=default_settings().header_table_size)


@dataclasses.dataclass(kw_only=True, slots=True)
class FrameHeader:
    length: int
    type: int
    flags: int
    stream_id: int
    failure: bool = False


@dataclasses.dataclass(kw_only=True, slots=True)
class Client:
    phase: int = 0
    rest_data: bytes = b""
    send_data: bytes = b""
    need_close: bool = False
    last_header: FrameHeader | None = None

    # TODO: MUST be received / sent first
    settings_received: bool = False
    local_settings: Settings = dataclasses.field(default_factory=default_settings)
    remote_settings: Settings = dataclasses.field(default_factory=default_settings)
    decoder: hpack.HPack = dataclasses.field(default_factory=default_decoder)

    streams: dict[int, Stream] = dataclasses.field(default_factory=default_streams)


class StreamState(enum.IntEnum):
    idle = 0
    reserved_local = 1
    reserved_remote = 2
    open = 3
    half_closed_remote = 4
    half_closed_local = 5
    closed = 6


@dataclasses.dataclass(kw_only=True, slots=True)
class Stream:
    identifier: int
    flow_control: int = 65_535
    state: StreamState = StreamState.idle


@dataclasses.dataclass(kw_only=True, slots=True)
class Settings:
    header_table_size: int = 4_096
    enable_push: int = 1
    max_concurrent_streams: int | None = None
    initial_window_size: int = 65_535
    max_frame_size: int = 16_384
    max_header_list_size: int | None = None


SETTING_MAPPING: Mapping[int, str] = {
    0x1: "header_table_size",
    0x2: "enable_push",
    0x3: "max_concurrent_streams",
    0x4: "initial_window_size",
    0x5: "max_frame_size",
    0x6: "max_header_list_size",
}
