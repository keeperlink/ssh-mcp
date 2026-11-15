"""Versioned, bounded and lossless compression of private SSH output chunks.

The byte offsets in jobs.output_bytes and output.offset are *always raw bytes*.
Keep audit/HTTP/MCP contracts independent of physical SQLite blob encoding.
"""
from __future__ import annotations

import zlib

RAW = "raw"
ZLIB_V1 = "zlib-v1"
MIN_SIZE = 1024
MIN_SAVING_RATIO = 0.85
MAX_RAW_CHUNK = 1048576  # Upper bound already enforced by SSH capture config.


class OutputCorruption(ValueError):
    """Safe, fixed error; do not include output bytes, actor or SQL content."""


def encode(data: bytes) -> tuple[bytes, str, int]:
    """Compress only if at least 1 KiB and at least 15% smaller."""
    size = len(data)
    if size > MAX_RAW_CHUNK:
        raise ValueError("Output chunk exceeds capture bound")
    if size >= MIN_SIZE:
        encoded = zlib.compress(data, level=6)
        if len(encoded) <= size * MIN_SAVING_RATIO:
            return encoded, ZLIB_V1, size
    return data, RAW, size


def decode(data: bytes, encoding: str, original_length: int | None) -> bytes:
    """Decode strictly within the raw limit; reject trailing/truncated zlib."""
    if (
        len(data) > MAX_RAW_CHUNK
        or original_length is not None
        and (type(original_length) is not int or not 0 <= original_length <= MAX_RAW_CHUNK)
    ):
        raise OutputCorruption("Invalid or corrupted stored output chunk")
    if encoding == RAW:
        if original_length is not None and len(data) != original_length:
            raise OutputCorruption("Invalid or corrupted stored output chunk")
        return data
    if encoding != ZLIB_V1 or original_length is None:
        raise OutputCorruption("Invalid or corrupted stored output chunk")
    try:
        inflater = zlib.decompressobj()
        result = inflater.decompress(data, original_length + 1)
        if (
            len(result) != original_length or not inflater.eof
            or inflater.unused_data or inflater.unconsumed_tail
        ):
            raise OutputCorruption("Invalid or corrupted stored output chunk")
        return result
    except zlib.error:
        raise OutputCorruption("Invalid or corrupted stored output chunk") from None
