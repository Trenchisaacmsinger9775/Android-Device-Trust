from dataclasses import dataclass

from app.protocol.codec import read_varint, parse_records, Record
from app.protocol.errors import DecodeError
from app.protocol.keys import derive_bytes, hash64, DOMAIN_PAYLOAD_CIPHER, MASK64

@dataclass(frozen=True)
class PayloadHeader:
    schema: int
    start_wall_ms: int
    start_mono_ns: int
    challenge_hash: bytes
    nonce: bytes
    header_bytes: bytes

@dataclass(frozen=True)
class DecodedPayload:
    header: PayloadHeader
    records: list[Record]

def _rotate_left(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (64 - bits))) & MASK64

def _next_word(state: list[int]) -> int:
    state[0] = (state[0] + state[1]) & MASK64
    state[3] ^= state[0]
    state[3] = _rotate_left(state[3], 32)
    state[2] = (state[2] + state[3]) & MASK64
    state[1] ^= state[2]
    state[1] = _rotate_left(state[1], 24)
    state[0] = (state[0] + state[1]) & MASK64
    state[3] ^= state[0]
    state[3] = _rotate_left(state[3], 16)
    state[2] = (state[2] + state[3]) & MASK64
    state[1] ^= state[2]
    state[1] = _rotate_left(state[1], 63)
    return state[0] ^ state[1] ^ state[2] ^ state[3]

def parse_header(data: bytes) -> PayloadHeader:
    if len(data) < 4 or data[:4] != b"DCA1":
        raise DecodeError("invalid payload magic")
    offset = 4
    header_version, offset = read_varint(data, offset)
    if header_version != 1:
        raise DecodeError("unsupported header version")
    schema, offset = read_varint(data, offset)
    if offset + 16 > len(data):
        raise DecodeError("truncated payload header")
    start_wall_ms = int.from_bytes(data[offset:offset + 8], "little", signed=False)
    offset += 8
    start_mono_ns = int.from_bytes(data[offset:offset + 8], "little", signed=False)
    offset += 8
    challenge_hash_length, offset = read_varint(data, offset)
    if offset + challenge_hash_length > len(data):
        raise DecodeError("truncated challenge hash")
    challenge_hash = data[offset:offset + challenge_hash_length]
    offset += challenge_hash_length
    nonce_length, offset = read_varint(data, offset)
    if offset + nonce_length > len(data):
        raise DecodeError("truncated nonce")
    nonce = data[offset:offset + nonce_length]
    offset += nonce_length
    return PayloadHeader(
        schema=schema,
        start_wall_ms=start_wall_ms,
        start_mono_ns=start_mono_ns,
        challenge_hash=challenge_hash,
        nonce=nonce,
        header_bytes=data[:offset],
    )

def unseal(data: bytes, challenge: bytes) -> DecodedPayload:
    if len(data) < 32:
        raise DecodeError("payload too short")
    header = parse_header(data)
    if len(data) < len(header.header_bytes) + 16:
        raise DecodeError("payload missing tag")

    sealed_without_tag = data[:-16]
    tag_a = int.from_bytes(data[-16:-8], "little", signed=False)
    tag_b = int.from_bytes(data[-8:], "little", signed=False)
    tag_input = sealed_without_tag + challenge
    expected_a = hash64(tag_input)
    expected_b = hash64(tag_input + b"\xA5")
    if tag_a != expected_a or tag_b != expected_b:
        raise DecodeError("payload tag mismatch")

    cipher = sealed_without_tag[len(header.header_bytes):]
    material = derive_bytes(DOMAIN_PAYLOAD_CIPHER, header.header_bytes + challenge, 32)
    state = [int.from_bytes(material[i:i + 8], "little", signed=False) for i in range(0, 32, 8)]
    body = bytearray(cipher)
    stream = 0
    for index in range(len(body)):
        if index % 8 == 0:
            stream = _next_word(state)
        body[index] ^= (stream >> ((index % 8) * 8)) & 0xFF
    return DecodedPayload(header=header, records=parse_records(bytes(body)))
