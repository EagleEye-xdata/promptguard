from backend.app.services.secrets import mask,protect,reveal


def test_target_credential_round_trip_and_masking():
    raw="Bearer test-secret-token-1234"
    encrypted=protect(raw,"unit-test-key")
    assert encrypted.startswith("enc:") and raw not in encrypted
    assert reveal(encrypted,"unit-test-key")==raw
    assert mask(encrypted)=="****(encrypted)"


def test_empty_key_preserves_local_demo_compatibility():
    assert protect("Bearer demo","")=="Bearer demo"
