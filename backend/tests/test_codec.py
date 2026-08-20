from app.protocol.codec import field_name
from app.protocol.fields import SIGNAL_IDS
from app.protocol.keys import derive_field_key

def test_dynamic_index_zero_fields_override_base_constant_names() -> None:
    assert field_name(derive_field_key(SIGNAL_IDS["ARRAY_ITEM_BASE"])) == "ARRAY_ITEM_0"
    assert field_name(derive_field_key(SIGNAL_IDS["KEY_ATTESTATION_CERT_ITEM_BASE"])) == "KEY_ATTESTATION_CERT_ITEM_0"
