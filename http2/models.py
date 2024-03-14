from __future__ import annotations

import dataclasses
import enum


def default_settings() -> Settings:
    # TODO: fill default settings
    return Settings()


def default_streams() -> dict[int, Stream]:
    return {0: Stream(identifier=0)}


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
    need_close: bool = False
    last_header: FrameHeader | None = None

    # TODO: MUST be received / sent first
    settings_received: bool = False
    settings: Settings = dataclasses.field(default_factory=default_settings)

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
    header_table_size: int = 1
    enable_push: int = 1
    max_concurrent_streams: int | None = None
    initial_window_size: int = 65_535
    max_frame_size: int = 16_384
    max_header_list_size: int | None = None
