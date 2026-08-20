from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ObjectIdentifier

from app.core.config import settings
from app.protocol.codec import Record

ANDROID_KEY_ATTESTATION_OID = ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

TAG_UNIVERSAL = 0
TAG_CONTEXT = 2

TAG_SEQUENCE = 16
TAG_SET = 17
TAG_INTEGER = 2
TAG_OCTET_STRING = 4
TAG_BOOLEAN = 1
TAG_ENUMERATED = 10

TAG_ROOT_OF_TRUST = 704
TAG_OS_VERSION = 705
TAG_OS_PATCH_LEVEL = 706
TAG_ATTESTATION_APPLICATION_ID = 709
TAG_VENDOR_PATCH_LEVEL = 718
TAG_BOOT_PATCH_LEVEL = 719

GOOGLE_ATTESTATION_ROOTS = (
    b"""-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----""",
    b"""-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----""",
)

@dataclass(frozen=True)
class AttestationDetails:
    status: str
    attestation_version: int | None = None
    attestation_security_level: str | None = None
    keymaster_version: int | None = None
    keymaster_security_level: str | None = None
    challenge_size: int | None = None
    challenge_matches: bool | None = None
    root_of_trust_present: bool = False
    device_locked: bool | None = None
    verified_boot_state: str | None = None
    verified_boot_hash_present: bool = False
    os_version: int | None = None
    os_patch_level: int | None = None
    vendor_patch_level: int | None = None
    boot_patch_level: int | None = None
    app_id_present: bool = False
    app_id_package_match: bool | None = None
    app_id_signature_match: bool | None = None
    app_id_package_count: int = 0
    app_id_signature_digest_count: int = 0
    chain_verified: bool = False
    root_trusted: bool = False
    root_sha256: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "attestation_version": self.attestation_version,
            "attestation_security_level": self.attestation_security_level,
            "keymaster_version": self.keymaster_version,
            "keymaster_security_level": self.keymaster_security_level,
            "challenge_size": self.challenge_size,
            "challenge_matches": self.challenge_matches,
            "root_of_trust_present": self.root_of_trust_present,
            "device_locked": self.device_locked,
            "verified_boot_state": self.verified_boot_state,
            "verified_boot_hash_present": self.verified_boot_hash_present,
            "os_version": self.os_version,
            "os_patch_level": self.os_patch_level,
            "vendor_patch_level": self.vendor_patch_level,
            "boot_patch_level": self.boot_patch_level,
            "app_id_present": self.app_id_present,
            "app_id_package_match": self.app_id_package_match,
            "app_id_signature_match": self.app_id_signature_match,
            "app_id_package_count": self.app_id_package_count,
            "app_id_signature_digest_count": self.app_id_signature_digest_count,
            "chain_verified": self.chain_verified,
            "root_trusted": self.root_trusted,
            "root_sha256": self.root_sha256,
        }

@dataclass(frozen=True)
class DerNode:
    tag_class: int
    constructed: bool
    tag: int
    value: bytes

def derive_attestation_details(records: list[Record], challenge: bytes | None = None) -> AttestationDetails:
    certs = _certificate_chain(records)
    if not certs:
        return AttestationDetails("missing_cert_chain")

    try:
        chain_verified, root_trusted, root_sha256 = _verify_chain(certs)
        certificate = _certificate_with_attestation_extension(certs)
        if certificate is None:
            return AttestationDetails("missing_extension", chain_verified=chain_verified, root_trusted=root_trusted, root_sha256=root_sha256)
        extension = certificate.extensions.get_extension_for_oid(ANDROID_KEY_ATTESTATION_OID)
        value = extension.value.value
    except x509.ExtensionNotFound:
        return AttestationDetails("missing_extension")
    except Exception:
        return AttestationDetails("invalid_certificate")

    try:
        root = _read_one(value)
        children = _children(root)
        if len(children) < 8:
            return AttestationDetails("invalid_extension")

        software = _authorization_list(children[6])
        tee = _authorization_list(children[7])
        root_of_trust = tee.get("root_of_trust") or software.get("root_of_trust") or {}
        app_id = tee.get("app_id") or software.get("app_id") or {}
        app_id_packages = app_id.get("packages", [])
        app_id_signature_digests = app_id.get("signature_digests", [])
        attestation_challenge = children[4].value if children[4].tag == TAG_OCTET_STRING else None
        return AttestationDetails(
            status="ok",
            attestation_version=_integer(children[0]),
            attestation_security_level=_security_level(_integer(children[1])),
            keymaster_version=_integer(children[2]),
            keymaster_security_level=_security_level(_integer(children[3])),
            challenge_size=len(attestation_challenge) if attestation_challenge is not None else None,
            challenge_matches=attestation_challenge == challenge if challenge is not None and attestation_challenge is not None else None,
            root_of_trust_present=bool(root_of_trust),
            device_locked=root_of_trust.get("device_locked"),
            verified_boot_state=root_of_trust.get("verified_boot_state"),
            verified_boot_hash_present=bool(root_of_trust.get("verified_boot_hash_present")),
            os_version=_first_int(tee, software, "os_version"),
            os_patch_level=_first_int(tee, software, "os_patch_level"),
            vendor_patch_level=_first_int(tee, software, "vendor_patch_level"),
            boot_patch_level=_first_int(tee, software, "boot_patch_level"),
            app_id_present=bool(app_id),
            app_id_package_match=_contains_package(app_id_packages, settings.expected_package_name) if app_id else None,
            app_id_signature_match=_contains_signature(app_id_signature_digests, settings.expected_app_certificate_sha256) if app_id else None,
            app_id_package_count=len(app_id_packages),
            app_id_signature_digest_count=len(app_id_signature_digests),
            chain_verified=chain_verified,
            root_trusted=root_trusted,
            root_sha256=root_sha256,
        )
    except Exception:
        return AttestationDetails("parse_failed")

def _authorization_list(node: DerNode) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for child in _children(node):
        if child.tag_class != TAG_CONTEXT:
            continue
        if child.tag == TAG_ROOT_OF_TRUST:
            out["root_of_trust"] = _root_of_trust(child)
        elif child.tag == TAG_OS_VERSION:
            out["os_version"] = _explicit_integer(child)
        elif child.tag == TAG_OS_PATCH_LEVEL:
            out["os_patch_level"] = _explicit_integer(child)
        elif child.tag == TAG_VENDOR_PATCH_LEVEL:
            out["vendor_patch_level"] = _explicit_integer(child)
        elif child.tag == TAG_BOOT_PATCH_LEVEL:
            out["boot_patch_level"] = _explicit_integer(child)
        elif child.tag == TAG_ATTESTATION_APPLICATION_ID:
            out["app_id"] = _attestation_app_id(child)
    return out

def _attestation_app_id(node: DerNode) -> dict[str, Any]:
    octet = _explicit_node(node)
    if octet.tag_class != TAG_UNIVERSAL or octet.tag != TAG_OCTET_STRING:
        return {}
    root = _read_one(octet.value)
    children = _children(root)
    if root.tag_class != TAG_UNIVERSAL or root.tag != TAG_SEQUENCE or len(children) < 2:
        return {}

    packages: list[dict[str, Any]] = []
    for package_info in _children(children[0]):
        info = _children(package_info)
        if len(info) < 2 or info[0].tag != TAG_OCTET_STRING:
            continue
        packages.append(
            {
                "name": info[0].value.decode("utf-8", errors="replace"),
                "version": _integer(info[1]),
            }
        )

    signature_digests = [
        digest.value.hex()
        for digest in _children(children[1])
        if digest.tag_class == TAG_UNIVERSAL and digest.tag == TAG_OCTET_STRING
    ]
    return {"packages": packages, "signature_digests": signature_digests}

def _root_of_trust(node: DerNode) -> dict[str, Any]:
    children = _children(_explicit_node(node))
    if len(children) < 3:
        return {}
    return {
        "device_locked": _boolean(children[1]),
        "verified_boot_state": _verified_boot_state(_integer(children[2])),
        "verified_boot_hash_present": len(children) >= 4 and children[3].tag == TAG_OCTET_STRING and bool(children[3].value),
    }

def _children(node: DerNode) -> list[DerNode]:
    children: list[DerNode] = []
    offset = 0
    while offset < len(node.value):
        child, offset = _read(node.value, offset)
        children.append(child)
    return children

def _explicit_node(node: DerNode) -> DerNode:
    children = _children(node)
    if not children:
        raise ValueError("empty explicit node")
    return children[0]

def _explicit_integer(node: DerNode) -> int | None:
    return _integer(_explicit_node(node))

def _integer(node: DerNode) -> int | None:
    if node.tag_class != TAG_UNIVERSAL or node.tag not in {TAG_INTEGER, TAG_ENUMERATED}:
        return None
    return int.from_bytes(node.value, "big", signed=False)

def _boolean(node: DerNode) -> bool | None:
    if node.tag_class != TAG_UNIVERSAL or node.tag != TAG_BOOLEAN or not node.value:
        return None
    return node.value[0] != 0

def _read_one(data: bytes) -> DerNode:
    node, offset = _read(data, 0)
    if offset != len(data):
        raise ValueError("trailing data")
    return node

def _read(data: bytes, offset: int) -> tuple[DerNode, int]:
    first = data[offset]
    offset += 1
    tag_class = first >> 6
    constructed = bool(first & 0x20)
    tag = first & 0x1F
    if tag == 0x1F:
        tag = 0
        while True:
            part = data[offset]
            offset += 1
            tag = (tag << 7) | (part & 0x7F)
            if part < 0x80:
                break

    length, offset = _read_length(data, offset)
    end = offset + length
    if end > len(data):
        raise ValueError("truncated value")
    return DerNode(tag_class, constructed, tag, data[offset:end]), end

def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4:
        raise ValueError("invalid length")
    return int.from_bytes(data[offset:offset + count], "big", signed=False), offset + count

def _security_level(value: int | None) -> str | None:
    if value == 0:
        return "Software"
    if value == 1:
        return "TrustedEnvironment"
    if value == 2:
        return "StrongBox"
    return None

def _verified_boot_state(value: int | None) -> str | None:
    if value == 0:
        return "Verified"
    if value == 1:
        return "SelfSigned"
    if value == 2:
        return "Unverified"
    if value == 3:
        return "Failed"
    return None

def _first_int(primary: dict[str, Any], secondary: dict[str, Any], key: str) -> int | None:
    value = primary.get(key)
    if isinstance(value, int):
        return value
    value = secondary.get(key)
    return value if isinstance(value, int) else None

def _contains_package(packages: list[dict[str, Any]], expected: str) -> bool:
    return any(package.get("name") == expected for package in packages)

def _contains_signature(signature_digests: list[str], expected: set[str]) -> bool:
    if not expected:
        return True
    return bool({digest.lower() for digest in signature_digests} & expected)

def _certificate_with_attestation_extension(certs: list[bytes]) -> x509.Certificate | None:
    for cert in certs:
        certificate = x509.load_der_x509_certificate(cert)
        try:
            certificate.extensions.get_extension_for_oid(ANDROID_KEY_ATTESTATION_OID)
            return certificate
        except x509.ExtensionNotFound:
            continue
    return None

def _verify_chain(certs: list[bytes]) -> tuple[bool, bool, str | None]:
    loaded = [x509.load_der_x509_certificate(cert) for cert in certs]
    if not loaded:
        return False, False, None

    trusted_roots = _trusted_roots()
    trusted_by_fingerprint = {_cert_sha256(root): root for root in trusted_roots}
    root_sha256 = _cert_sha256(loaded[-1])
    root_trusted = root_sha256 in trusted_by_fingerprint
    chain = loaded

    if not root_trusted:
        appended = _matching_trusted_root(loaded[-1], trusted_roots)
        if appended is not None:
            root_trusted = True
            root_sha256 = _cert_sha256(appended)
            chain = loaded + [appended]

    if not root_trusted:
        return False, False, root_sha256

    for index in range(len(chain) - 1):
        if chain[index].issuer != chain[index + 1].subject:
            return False, True, root_sha256
        if not _verify_certificate_signature(chain[index], chain[index + 1]):
            return False, True, root_sha256

    root = chain[-1]
    if not _verify_certificate_signature(root, root):
        return False, True, root_sha256
    return True, True, root_sha256

def _matching_trusted_root(certificate: x509.Certificate, trusted_roots: list[x509.Certificate]) -> x509.Certificate | None:
    for root in trusted_roots:
        if certificate.issuer != root.subject:
            continue
        if _verify_certificate_signature(certificate, root):
            return root
    return None

def _trusted_roots() -> list[x509.Certificate]:
    return [x509.load_pem_x509_certificate(root) for root in GOOGLE_ATTESTATION_ROOTS]

def _cert_sha256(certificate: x509.Certificate) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(certificate.public_bytes(serialization.Encoding.DER))
    return digest.finalize().hex()

def _verify_certificate_signature(certificate: x509.Certificate, issuer: x509.Certificate) -> bool:
    public_key = issuer.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
            return True
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm),
            )
            return True
    except Exception:
        return False
    return False

def _certificate_chain(records: list[Record]) -> list[bytes]:
    chain = _record(records, "KEY_ATTESTATION_CERT_CHAIN")
    if chain is None or not isinstance(chain.value, list):
        return []

    certs: list[tuple[int, bytes]] = []
    for record in chain.value:
        if not record.name.startswith("KEY_ATTESTATION_CERT_ITEM_"):
            continue
        if not isinstance(record.value, bytes):
            continue
        index_text = record.name.rsplit("_", 1)[1]
        if not index_text.isdigit():
            continue
        certs.append((int(index_text), record.value))
    return [value for _, value in sorted(certs)]

def _record(records: list[Record], name: str) -> Record | None:
    for record in records:
        if record.name == name:
            return record
    return None
