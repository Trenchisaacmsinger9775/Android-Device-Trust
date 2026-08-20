from dataclasses import dataclass
from typing import Any
import zlib

from app.protocol.errors import DecodeError
from app.protocol.keys import derive_field_key
from app.protocol.fields import SIGNAL_IDS

TYPE_BYTES = 1
TYPE_STRING = 2
TYPE_UINT64 = 3
TYPE_INT64 = 4
TYPE_DOUBLE = 5
TYPE_NESTED = 6
TYPE_HASHED_BYTES = 7
FLAG_ZLIB = 1

FIELD_NAMES_BY_KEY = {derive_field_key(value): name for name, value in SIGNAL_IDS.items()}

@dataclass(frozen=True)
class Record:
    name: str
    key: bytes
    type: int
    flags: int
    payload: bytes
    value: Any

def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
        if shift > 63:
            raise DecodeError("varint too large")
    raise DecodeError("truncated varint")

def parse_records(data: bytes) -> list[Record]:
    records: list[Record] = []
    offset = 0
    while offset < len(data):
        key_length, offset = read_varint(data, offset)
        if key_length <= 0 or offset + key_length + 2 > len(data):
            raise DecodeError("invalid record key")
        key = data[offset:offset + key_length]
        offset += key_length
        record_type = data[offset]
        flags = data[offset + 1]
        offset += 2
        payload_length, offset = read_varint(data, offset)
        if offset + payload_length > len(data):
            raise DecodeError("truncated record payload")
        payload = data[offset:offset + payload_length]
        offset += payload_length
        name = field_name(key)
        value = decode_value(record_type, payload)
        records.append(Record(name=name, key=key, type=record_type, flags=flags, payload=payload, value=value))
    return records

def field_name(key: bytes) -> str:
    for index in range(128):
        if derive_field_key(SIGNAL_IDS["ARRAY_ITEM_BASE"] + index) == key:
            return f"ARRAY_ITEM_{index}"
        if derive_field_key(SIGNAL_IDS["KEY_ATTESTATION_CERT_ITEM_BASE"] + index) == key:
            return f"KEY_ATTESTATION_CERT_ITEM_{index}"
        if derive_field_key(SIGNAL_IDS["KEY_IDENTITY_CERT_ITEM_BASE"] + index) == key:
            return f"KEY_IDENTITY_CERT_ITEM_{index}"
    name = FIELD_NAMES_BY_KEY.get(key)
    if name is not None:
        return name
    return f"UNKNOWN_{key.hex()}"

def decode_value(record_type: int, payload: bytes) -> Any:
    if record_type == TYPE_BYTES:
        return payload
    if record_type == TYPE_STRING:
        return payload.decode("utf-8", errors="replace")
    if record_type == TYPE_UINT64:
        return int.from_bytes(payload[:8], "little", signed=False) if len(payload) >= 8 else None
    if record_type == TYPE_INT64:
        return int.from_bytes(payload[:8], "little", signed=True) if len(payload) >= 8 else None
    if record_type == TYPE_NESTED:
        return parse_records(payload)
    if record_type == TYPE_HASHED_BYTES and len(payload) >= 17:
        return {
            "present": payload[0] == 1,
            "size": int.from_bytes(payload[1:9], "little", signed=False),
            "hash64": int.from_bytes(payload[9:17], "little", signed=False),
        }
    return payload

def flatten(records: list[Record]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for record in records:
        if isinstance(record.value, list):
            out[record.name] = flatten(record.value)
        elif isinstance(record.value, bytes):
            value = {"bytes": len(record.value)}
            if record.flags & FLAG_ZLIB:
                try:
                    value["zlib_bytes"] = len(zlib.decompress(record.value))
                except zlib.error:
                    value["zlib_error"] = True
            out[record.name] = value
        else:
            out[record.name] = record.value
    return out
