import base64
import hashlib
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.protocol.codec import Record

@dataclass(frozen=True)
class DeviceIdentity:
    device_instance_id: str | None
    status: str
    public_key_sha256: str | None = None
    leaf_cert_sha256: str | None = None
    cert_count: int = 0
    signature_verified: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "device_instance_id": self.device_instance_id,
            "status": self.status,
            "public_key_sha256": self.public_key_sha256,
            "leaf_cert_sha256": self.leaf_cert_sha256,
            "cert_count": self.cert_count,
            "signature_verified": self.signature_verified,
        }

def derive_device_identity(records: list[Record], challenge: bytes) -> DeviceIdentity:
    certs = _certificate_chain(records, "KEY_IDENTITY_CERT_CHAIN", "KEY_IDENTITY_CERT_ITEM_")
    signature = _bytes_value(records, "KEY_IDENTITY_SIGNATURE")
    if not certs:
        return DeviceIdentity(None, "missing_cert_chain")
    if not signature:
        return DeviceIdentity(None, "missing_signature", cert_count=len(certs))

    try:
        leaf = x509.load_der_x509_certificate(certs[0])
        public_key = leaf.public_key()
        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception:
        return DeviceIdentity(None, "invalid_leaf_certificate", cert_count=len(certs))

    public_key_sha256 = hashlib.sha256(public_key_der).hexdigest()
    leaf_cert_sha256 = hashlib.sha256(certs[0]).hexdigest()
    device_instance_id = _identifier(public_key_der)

    try:
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return DeviceIdentity(
                device_instance_id,
                "unsupported_public_key_type",
                public_key_sha256,
                leaf_cert_sha256,
                len(certs),
                False,
            )
        public_key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return DeviceIdentity(
            device_instance_id,
            "signature_invalid",
            public_key_sha256,
            leaf_cert_sha256,
            len(certs),
            False,
        )
    except Exception:
        return DeviceIdentity(
            device_instance_id,
            "signature_verification_failed",
            public_key_sha256,
            leaf_cert_sha256,
            len(certs),
            False,
        )

    return DeviceIdentity(
        device_instance_id,
        "ok",
        public_key_sha256,
        leaf_cert_sha256,
        len(certs),
        True,
    )

def _identifier(public_key_der: bytes) -> str:
    digest = hashlib.sha256(b"devicecheck-device-instance-v1" + public_key_der).digest()
    return base64.urlsafe_b64encode(digest[:18]).decode("ascii").rstrip("=")

def _certificate_chain(records: list[Record], chain_name: str, item_prefix: str) -> list[bytes]:
    chain = _record(records, chain_name)
    if chain is None or not isinstance(chain.value, list):
        return []

    certs: list[tuple[int, bytes]] = []
    for record in chain.value:
        if not record.name.startswith(item_prefix):
            continue
        if not isinstance(record.value, bytes):
            continue
        index_text = record.name.rsplit("_", 1)[1]
        if not index_text.isdigit():
            continue
        index = int(index_text)
        certs.append((index, record.value))
    return [value for _, value in sorted(certs)]

def _bytes_value(records: list[Record], name: str) -> bytes | None:
    record = _record(records, name)
    if record is None or not isinstance(record.value, bytes):
        return None
    return record.value

def _record(records: list[Record], name: str) -> Record | None:
    for record in records:
        if record.name == name:
            return record
    return None
