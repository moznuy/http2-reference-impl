# 6 bytes:
# 16 bit identifier
# 32 bit value
import dataclasses
import struct
from collections.abc import Mapping
from typing import Protocol

from http2 import models

SETTINGS_FRAME_FORMAT = ">HI"
SETTINGS_FRAME_FORMAT_SIZE = struct.calcsize(SETTINGS_FRAME_FORMAT)
assert SETTINGS_FRAME_FORMAT_SIZE == 6


def sizeof_fmt(num, suffix="B"):
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


@dataclasses.dataclass(kw_only=True, slots=True)
class SettingRaw:
    identifier: int
    value: int


def set_settings(client: models.Client, setting: SettingRaw) -> bool:
    # TODO: set setting; return success
    #     # The SETTINGS frame affects connection state.  A badly formed or
    #     # incomplete SETTINGS frame MUST be treated as a connection error
    #     # (Section 5.4.1) of type PROTOCOL_ERROR.
    return True


def parse_settings(client: models.Client, header: models.FrameHeader, frame: bytes):
    assert frame is not None
    assert header is not None
    assert header.type == 0x4
    assert len(frame) == header.length

    if header.flags & 0x1:  # Settings ACK frame
        if len(frame) > 0 or header.length > 0:
            # TODO: set connection error FRAME_SIZE_ERROR
            print("Settings ACK frame is not empty")
            client.need_close = True
            return
        print("Settings ACK")
        return

    # The stream identifier for a SETTINGS frame MUST be zero (0x0)
    if header.stream_id != 0:
        # TODO: set connection error PROTOCOL_ERROR
        print("Settings frame stream id != 0")
        client.need_close = True
        return

    # TODO: ????
    # The SETTINGS frame affects connection state.  A badly formed or
    # incomplete SETTINGS frame MUST be treated as a connection error
    # (Section 5.4.1) of type PROTOCOL_ERROR.

    if header.length % SETTINGS_FRAME_FORMAT_SIZE != 0:
        # TODO: set connection error FRAME_SIZE_ERROR
        print("Settings frame length is not multiple of 6")
        client.need_close = True
        return

    # count = header.length // 6
    setting_raw: tuple[int, int]
    for setting_raw in struct.iter_unpack(SETTINGS_FRAME_FORMAT, frame):
        setting = SettingRaw(identifier=setting_raw[0], value=setting_raw[1])
        if not set_settings(client, setting):
            # TODO: PROTOCOL_ERROR
            client.need_close = True
            return
    print("Settings frame OK")


def window_update(client: models.Client, stream_id: int, incr: int) -> None:
    stream = client.streams.get(stream_id)
    # TODO:
    #   Receiving any frame other than HEADERS or PRIORITY on a stream in
    #   this state MUST be treated as a connection error (Section 5.4.1)
    #   of type PROTOCOL_ERROR.
    if stream is None:
        print("Window update: Stream not found")
        client.need_close = True
        return

    stream.flow_control += incr
    if stream.flow_control > 2**31 - 1:
        # TODO: must terminate stream or connection
        #  For streams, the sender
        #  sends a RST_STREAM with an error code of FLOW_CONTROL_ERROR; for the
        #  connection, a GOAWAY frame with an error code of FLOW_CONTROL_ERROR
        #  is sent.
        print(
            "Window update: flow_control > 2 ** 31 - 1",
            stream.flow_control,
            2**31 - 1,
        )
        client.need_close = True
        return
    print("Window update: ", stream.identifier, sizeof_fmt(stream.flow_control))


def parse_window_update(
    client: models.Client, header: models.FrameHeader, frame: bytes
):
    assert frame is not None
    assert header is not None
    assert header.type == 0x8
    assert len(frame) == header.length

    raw: tuple[int]
    raw = struct.unpack_from(f">I", frame, 0)
    # Only 31 bit
    window_size_increment = raw[0] & 0x7F_FF_FF_FF

    if window_size_increment < 1 or window_size_increment > 2**31 - 1:
        # TODO: MUST PROTOCOL_ERROR on stream or connection error on stream 0
        print("Invalid window size increment")
        client.need_close = True
        return

    if header.length != 4:
        # TODO: must connection error with FRAME_SIZE_ERROR
        print("Invalid window update frame")
        client.need_close = True
        return

    window_update(client, header.stream_id, window_size_increment)
    print("Window update frame OK")


def parse_headers(client: models.Client, header: models.FrameHeader, frame: bytes):
    assert frame is not None
    assert header is not None
    assert header.type == 0x1
    assert len(frame) == header.length

    print(header, frame)


def parse_unknown(client: models.Client, header: models.FrameHeader, frame: bytes):
    print("Unknown frame", header, frame)


class ParsingProtocol(Protocol):
    def __call__(
        self, client: models.Client, header: models.FrameHeader, frame: bytes
    ) -> None:
        ...


FRAME_MAPPING: Mapping[int, ParsingProtocol] = {
    0x1: parse_headers,
    0x4: parse_settings,
    0x8: parse_window_update,
}
