def test_validators_loaded():
    import aleph.sdk.security as security
    assert any([validator is not None for validator in security.validators.values()])
