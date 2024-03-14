from __future__ import annotations

import dataclasses
import socket
import struct
from collections.abc import Mapping
from typing import Protocol

CLIENT_PREFACE_PRI = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


@dataclasses.dataclass(kw_only=True, slots=True)
class FrameHeader:
    length: int
    type: int
    flags: int
    stream_id: int
    failure: bool = False


# All numbers are big endian

# 9 bytes:
# 24 bit length
# 8 bit type
# 8 bit flags
# 1 bit reserved 0
# 31 bit stream identifier
FRAME_HEADER_FORMAT = ">3sBBI"
FRAME_HEADER_FORMAT_SIZE = struct.calcsize(FRAME_HEADER_FORMAT)
assert FRAME_HEADER_FORMAT_SIZE == 9


def parse_frame_header(client) -> FrameHeader | None:
    if len(client.rest_data) < FRAME_HEADER_FORMAT_SIZE:
        return None

    # header_raw, client.rest_data = client.rest_data[:9], client.rest_data[9:]
    res: tuple[bytes, int, int, int]
    res = struct.unpack_from(FRAME_HEADER_FORMAT, client.rest_data)
    client.rest_data = client.rest_data[FRAME_HEADER_FORMAT_SIZE:]
    header = FrameHeader(
        length=int.from_bytes(res[0], "big", signed=False),
        type=res[1],
        flags=res[2],
        stream_id=res[3],
    )
    # TODO: SETTINGS_MAX_FRAME_SIZE
    if header.length > 2**14:
        print("Header length > 2 ^ 14", header.length, 2**14)
        header.failure = True
    # TODO: Check frame type for unknown and MUST skip

    if header.stream_id & 0x80_00_00_00:
        print("Reserved bit is set")
        header.failure = True
    return header


def parse_frame_body(client: Client) -> bytes | None:
    assert client.last_header is not None
    assert not client.last_header.failure

    length = client.last_header.length
    if len(client.rest_data) < length:
        return
    frame, client.rest_data = client.rest_data[:length], client.rest_data[length:]
    return frame


def default_settings() -> Settings:
    # TODO: fill default settings
    return Settings()


def default_streams() -> dict[int, Stream]:
    return {0: Stream()}


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


@dataclasses.dataclass(kw_only=True, slots=True)
class Stream:
    flow_control: int = 65_535


@dataclasses.dataclass(kw_only=True, slots=True)
class Settings:
    header_table_size: int = 1
    enable_push: int = 1
    max_concurrent_streams: int | None = None
    initial_window_size: int = 65_535
    max_frame_size: int = 16_384
    max_header_list_size: int | None = None


@dataclasses.dataclass(kw_only=True, slots=True)
class SettingRaw:
    identifier: int
    value: int


def set_settings(client: Client, setting: SettingRaw) -> bool:
    # TODO: set setting; return success
    #     # The SETTINGS frame affects connection state.  A badly formed or
    #     # incomplete SETTINGS frame MUST be treated as a connection error
    #     # (Section 5.4.1) of type PROTOCOL_ERROR.
    return True


# 6 bytes:
# 16 bit identifier
# 32 bit value
SETTINGS_FRAME_FORMAT = ">HI"
SETTINGS_FRAME_FORMAT_SIZE = struct.calcsize(SETTINGS_FRAME_FORMAT)
assert SETTINGS_FRAME_FORMAT_SIZE == 6


def parse_settings(client: Client, header: FrameHeader, frame: bytes):
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


def parse_unknown(client: Client, header: FrameHeader, frame: bytes):
    print("Unknown frame", header, frame)


class ParsingProtocol(Protocol):
    def __call__(self, client: Client, header: FrameHeader, frame: bytes) -> None:
        ...


FRAME_MAPPING: Mapping[int, ParsingProtocol] = {
    0x4: parse_settings,
}


def handle_client(client: Client) -> None:
    assert not client.need_close

    while True:
        if client.phase == 0:
            print("Client phase 0")
            if len(client.rest_data) < len(CLIENT_PREFACE_PRI):
                return
            if not client.rest_data.startswith(CLIENT_PREFACE_PRI):
                print("Not http/2 with prior knowledge")
                client.need_close = True
                return
            client.rest_data = client.rest_data[len(CLIENT_PREFACE_PRI) :]
            client.phase = 1

        if client.phase == 1:
            print("Client phase 1")
            header = parse_frame_header(client)
            if header is None:
                return
            if header.failure:
                print("Header failure")
                client.need_close = True
                return
            client.last_header = header
            client.phase = 2

        if client.phase == 2:
            print("Client phase 2")
            frame = parse_frame_body(client)
            if frame is None:
                return
            header = client.last_header
            client.last_header = None

            # TODO: map type -> function
            parser = FRAME_MAPPING.get(header.type, parse_unknown)
            parser(client, header, frame)

            client.phase = 1
            continue

        raise NotImplementedError


def main():
    server_sock = socket.create_server(("127.0.0.1", 8000), reuse_port=True)
    print("Listening on port 8000")
    while True:
        client_sock, addr = server_sock.accept()
        print("Client open")
        client = Client()
        while True:
            payload = client_sock.recv(4096)
            if not payload:
                break
            client.rest_data += payload
            handle_client(client)
            if client.need_close:
                print("Need close")
                break

        if client.rest_data:
            print("Unhandled data in client steam before close")
        print("Client closed")
        client_sock.close()


if __name__ == "__main__":
    main()
