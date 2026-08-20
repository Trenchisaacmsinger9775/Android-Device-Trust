SCHEMA_VERSION = 1
DOMAIN_FIELD_KEY = 0x5F456F88A77105C9
DOMAIN_CHALLENGE_HASH = 0xB05152410320104F
DOMAIN_PAYLOAD_CIPHER = 0x8034F7A1C55B651D

MASTER_A = 0x8F3D3A7E2C9B1051
MASTER_B = 0xD64A6D1A9E3779B9
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
MASK64 = 0xFFFFFFFFFFFFFFFF

def mix64(value: int) -> int:
    value &= MASK64
    value ^= value >> 30
    value = (value * 0xBF58476D1CE4E5B9) & MASK64
    value ^= value >> 27
    value = (value * 0x94D049BB133111EB) & MASK64
    value ^= value >> 31
    return value & MASK64

def hash64(data: bytes) -> int:
    value = FNV_OFFSET
    for byte in data:
        value ^= byte
        value = (value * FNV_PRIME) & MASK64
    return mix64(value ^ MASTER_A)

def uint64_le(value: int) -> bytes:
    return int(value & MASK64).to_bytes(8, "little", signed=False)

def derive_bytes(domain: int, data: bytes, length: int) -> bytes:
    seed = uint64_le(domain) + bytes([SCHEMA_VERSION]) + data
    state_a = hash64(seed) ^ MASTER_A
    state_b = mix64(state_a ^ MASTER_B ^ len(data))
    out = bytearray()
    while len(out) < length:
        state_a = mix64(state_a + 0x9E3779B97F4A7C15 + state_b)
        state_b = mix64(state_b ^ state_a ^ 0xD1B54A32D192ED03)
        out.extend(uint64_le(state_a ^ state_b))
    return bytes(out[:length])

def derive_field_key(field_id: int) -> bytes:
    return derive_bytes(DOMAIN_FIELD_KEY, uint64_le(field_id), 16)
