from __future__ import annotations

import dataclasses
from collections.abc import Iterator

from http2 import huffman


@dataclasses.dataclass(slots=True, kw_only=True, frozen=True)
class Header:
    key: str
    value: str | None


# TODO:    Indices strictly greater than the sum of the lengths of both tables
#    MUST be treated as a decoding error.

STATIC_TABLE: list[Header | None] = [
    None,
    Header(key=":authority", value=None),
    Header(key=":method", value="GET"),
    Header(key=":method", value="POST"),
    Header(key=":path", value="/"),
    Header(key=":path", value="/index.html"),
    Header(key=":scheme", value="http"),
    Header(key=":scheme", value="https"),
    Header(key=":status", value="200"),
    Header(key=":status", value="204"),
    Header(key=":status", value="206"),
    Header(key=":status", value="304"),
    Header(key=":status", value="400"),
    Header(key=":status", value="404"),
    Header(key=":status", value="500"),
    Header(key="accept-charset", value=None),
    Header(key="accept-encoding", value="gzip, deflate"),
    Header(key="accept-language", value=None),
    Header(key="accept-ranges", value=None),
    Header(key="accept", value=None),
    Header(key="access-control-allow-origin", value=None),
    Header(key="age", value=None),
    Header(key="allow", value=None),
    Header(key="authorization", value=None),
    Header(key="cache-control", value=None),
    Header(key="content-disposition", value=None),
    Header(key="content-encoding", value=None),
    Header(key="content-language", value=None),
    Header(key="content-length", value=None),
    Header(key="content-location", value=None),
    Header(key="content-range", value=None),
    Header(key="content-type", value=None),
    Header(key="cookie", value=None),
    Header(key="date", value=None),
    Header(key="etag", value=None),
    Header(key="expect", value=None),
    Header(key="expires", value=None),
    Header(key="from", value=None),
    Header(key="host", value=None),
    Header(key="if-match", value=None),
    Header(key="if-modified-since", value=None),
    Header(key="if-none-match", value=None),
    Header(key="if-range", value=None),
    Header(key="if-unmodified-since", value=None),
    Header(key="last-modified", value=None),
    Header(key="link", value=None),
    Header(key="location", value=None),
    Header(key="max-forwards", value=None),
    Header(key="proxy-authenticate", value=None),
    Header(key="proxy-authorization", value=None),
    Header(key="range", value=None),
    Header(key="referer", value=None),
    Header(key="refresh", value=None),
    Header(key="retry-after", value=None),
    Header(key="server", value=None),
    Header(key="set-cookie", value=None),
    Header(key="strict-transport-security", value=None),
    Header(key="transfer-encoding", value=None),
    Header(key="user-agent", value=None),
    Header(key="vary", value=None),
    Header(key="via", value=None),
    Header(key="www-authenticate", value=None),
]

assert len(STATIC_TABLE[1:]) == 61


class HPack:
    def __init__(self, max_table_size: int):
        # self.result: list[Header] = []
        self.max_table_size = max_table_size
        # self.new_max_table_size: int | None = None
        # TODO: To limit the
        #    memory requirements of the decoder, the dynamic table size is
        #    strictly bounded (see Section 4.2).

        # FIFO
        # TODO: The header field is inserted at the beginning of the dynamic
        #       table.  This insertion could result in the eviction of previous
        #       entries in the dynamic table (see Section 4.4).

        # TODO:    The size of the dynamic table is the sum of the size of its entries.
        #    The size of an entry is the sum of its name's length in octets (as
        #    defined in Section 5.2), its value's length in octets, and 32.
        #    The size of an entry is calculated using the length of its name and
        #    value without any Huffman encoding applied.

        # -1 will be the first entry to not to insert into index 0, but to the end
        # self.dynamic_table = ""
        # self.dynamic_indexes: list[tuple[int, int]] = []
        self.dynamic_indexes: list[Header] = []
        print("HPack INIT")

    def change_max_table_size(self, max_table_size: int):
        self.max_table_size = max_table_size
        # TODO: change dynamic table accordingly
        #  This ensures that the
        #    decoder is able to perform eviction based on reductions in dynamic
        #    table size (see Section 4.3).
        #    This mechanism can be used to completely clear entries from the
        #    dynamic table by setting a maximum size of 0, which can subsequently
        #    be restored.
        #    Whenever the maximum size for the dynamic table is reduced, entries
        #    are evicted from the end of the dynamic table until the size of the
        #    dynamic table is less than or equal to the maximum size.

    def change_table_size(self, table_size: int):
        pass

    def add_to_dynamic_table(self, header: Header):
        # todo:    Before a new entry is added to the dynamic table, entries are evicted
        #    from the end of the dynamic table until the size of the dynamic table
        #    is less than or equal to (maximum size - new entry size) or until the
        #    table is empty.
        #   If the size of the new entry is less than or equal to the maximum
        #   size, that entry is added to the table.  It is not an error to
        #   a ttempt to add an entry that is larger than the maximum size; an
        #   attempt to add an entry larger than the maximum size causes the table
        #   to be emptied of all existing entries and results in an empty table.
        self.dynamic_indexes.append(header)

    def get_from_tables(
        self, index: int, value_must: bool
    ) -> tuple[bool, int | Header]:
        assert index > 0
        if index < len(STATIC_TABLE):
            header = STATIC_TABLE[index]
            if value_must and header.value is None:
                return False, -7
            return True, header

        index -= len(STATIC_TABLE)
        if index >= len(self.dynamic_indexes):
            return False, -6

        header = self.dynamic_indexes[-index - 1]
        if value_must and header.value is None:
            return False, -8
        return True, header

    def decode(self, data: bytes) -> Iterator[tuple[bool, int | Header]]:
        can_dyn_change = True
        while True:
            if not data:
                return

            byte, data = data[0], data[1:]

            # Indexed Header Field
            if (byte >> 7) == 1:
                can_dyn_change = False
                success, index, data = decode_int(7, byte & 0x7F, data)
                if not success:
                    yield False, index
                    return

                if index == 0:
                    yield False, -5
                    return

                success, header = self.get_from_tables(index, value_must=True)
                yield success, header
                if not success:
                    return

                continue

            # Literal Header Field with Incremental Indexing
            if (byte >> 6) == 1:
                can_dyn_change = False
                success, index, data = decode_int(6, byte & 0x3F, data)
                if not success:
                    yield False, index
                    return

                if index == 0:  # field name is represented as a string literal
                    success, header_key, data = decode_str(data)
                    if not success:
                        yield False, header_key
                else:
                    success, header = self.get_from_tables(index, value_must=False)
                    if not success:
                        yield False, header
                    header_key: str = header.key

                success, header_value, data = decode_str(data)
                if not success:
                    yield False, header_value

                header = Header(key=header_key, value=header_value)
                self.add_to_dynamic_table(header)  # TODO: check error
                yield True, header
                continue

            # Literal Header Field without Indexing; Literal Header Field Never Indexed
            if (byte >> 4) in [0, 1]:
                # TODO: something with: Intermediaries MUST use the same representation
                #    for encoding this header field.
                # TODO: same code
                can_dyn_change = False
                success, index, data = decode_int(4, byte & 0x0F, data)
                if not success:
                    yield False, index
                    return

                if index == 0:  # field name is represented as a string literal
                    success, header_key, data = decode_str(data)
                    if not success:
                        yield False, header_key
                else:
                    success, header = self.get_from_tables(index, value_must=False)
                    if not success:
                        yield False, header
                    header_key: str = header.key

                success, header_value, data = decode_str(data)
                if not success:
                    yield False, header_value

                header = Header(key=header_key, value=header_value)
                self.add_to_dynamic_table(header)  # TODO: check error
                yield True, header
                continue

            # Dynamic Table Size Update
            if (byte >> 5) == 1:
                # Updates can occur only at the beginning of the block
                if not can_dyn_change:
                    yield False, -14
                    return

                success, size, data = decode_int(5, byte & 0x1F, data)
                if not success:
                    yield False, size
                    return
                if size > self.max_table_size:
                    yield False, -9
                    return
                self.change_table_size(size)
                print("HPACK: Dynamic Table Size Update", size)
                continue

            raise NotImplementedError

    # def finalize(self) -> dict[str, list[str]]:
    #     return self.result


def decode_int(n_bits: int, first_byte: int, data: bytes) -> tuple[bool, int, bytes]:
    # i, data = data[0], data[1:]
    i = first_byte
    if i < 2**n_bits - 1:
        return True, i, data

    m = 0
    while True:
        if not data:
            return False, -1, data

        b, data = data[0], data[1:]
        i = i + (b & 127) * 2**m
        m += 7
        if b & 128 != 128:
            break

    if i > 2**32 - 1:
        return False, -2, data
    return True, i, data


def decode_str(data: bytes) -> tuple[bool, str | int, bytes]:
    if not data:
        return False, -3, data

    first_byte, data = data[0], data[1:]
    _huffman = (first_byte & 0b1000_0000) != 0  # TODO: is it MSB or LSB? probably MSB
    success, length, data = decode_int(7, first_byte & 0x7F, data)
    if not success:
        return False, length, data

    if len(data) < length:
        return False, -4, data
    raw, data = data[:length], data[length:]

    if not _huffman:
        s = raw.decode()
        return True, s, data

    success, s = huffman.decode_huffman(raw)
    return success, s, data
