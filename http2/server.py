from __future__ import annotations

import socket
import struct

from http2 import frames
from http2 import models

CLIENT_PREFACE_PRI = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


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


def parse_frame_header(client) -> models.FrameHeader | None:
    if len(client.rest_data) < FRAME_HEADER_FORMAT_SIZE:
        return None

    # header_raw, client.rest_data = client.rest_data[:9], client.rest_data[9:]
    res: tuple[bytes, int, int, int]
    res = struct.unpack_from(FRAME_HEADER_FORMAT, client.rest_data)
    client.rest_data = client.rest_data[FRAME_HEADER_FORMAT_SIZE:]
    header = models.FrameHeader(
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


def parse_frame_body(client: models.Client) -> bytes | None:
    assert client.last_header is not None
    assert not client.last_header.failure

    length = client.last_header.length
    if len(client.rest_data) < length:
        return
    frame, client.rest_data = client.rest_data[:length], client.rest_data[length:]
    return frame


def handle_client(client: models.Client) -> None:
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
            parser = frames.FRAME_MAPPING.get(header.type, frames.parse_unknown)
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
        client = models.Client()
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
