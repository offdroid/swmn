from typing import Optional, List


def _parse_case():
    assert str(__name__).startswith(
        "case_"), "Module must adhere to naming convention"
    id: str = str(__name__)[len("case_"):]
    return int(id)


def make_cert(cn: str, passphrase: Optional[str], ca_passphrase: str, data):
    case = _parse_case()
    if case == 1:
        assert cn == "test", "Common name must match"
        assert passphrase == "1234", "Certifiacte passphrase must match"
        assert ca_passphrase == "5678", "CA passphrase must match"
        assert data == None, "Extra data must match"
        return True
    elif case == 2:
        assert cn == "what", "Common name must match"
        assert passphrase == None, "No certificate passphrase must be provided"
        assert ca_passphrase == "abcdef", "CA passphrase must match"
        assert isinstance(data, dict), "Extra data must be a dict"
        assert len(data) == 0, "Extra data must be a empty"
    elif case == 3:
        assert cn == "which", "Common name must match"
        assert passphrase == "this", "Certifiacte passphrase must match"
        assert ca_passphrase == "qwerty", "CA passphrase must match"
        assert isinstance(data, dict), "Extra data must be a dict"
        assert len(data) == 2, "Extra data must be a empty"
        assert data["key"] == "value", "Missing or wrong key-value pair"
        assert data["one"] == "two", "Missing or wrong key-value pair"
    elif case == 4:
        raise RuntimeError("Sample error that occured during execution")
    else:
        raise ValueError("Unknown test case")


def _rrc(cn: str, ca_passphrase: str, data):
    case = _parse_case()
    if case == 1:
        assert cn == "test", "Common name must match"
        assert ca_passphrase == "5678", "CA passphrase must match"
        assert data == None, "Extra data must match"
    elif case == 2:
        assert cn == "what", "Common name must match"
        assert ca_passphrase == "abcdef", "CA passphrase must match"
        assert isinstance(data, dict), "Extra data must be a dict"
        assert len(data) == 0, "Extra data must be a empty"
    elif case == 3:
        assert cn == "which", "Common name must match"
        assert ca_passphrase == "qwerty", "CA passphrase must match"
        assert isinstance(data, dict), "Extra data must be a dict"
        assert len(data) == 2, "Extra data must be a empty"
        assert data["key"] == "value", "Missing or wrong key-value pair"
        assert data["one"] == "two", "Missing or wrong key-value pair"
    elif case == 4:
        raise RuntimeError("Sample error that occured during execution")
    else:
        raise ValueError("Unknown test case")


def revoke_cent(cn: str, ca_passphrase: str, data):
    return _rrc(cn, ca_passphrase, data)


def revoke_and_remove_cert(cn: str, ca_passphrase: str, data):
    return _rrc(cn, ca_passphrase, data)


def list_certs(data) -> List[str]:
    case = _parse_case()
    if case == 1:
        assert data == None, "Extra data must match"
        return ["test"]
    elif case == 2:
        assert isinstance(data, dict), "Extra data must be a dict"
        assert len(data) == 0, "Extra data must be a empty"
        return ["what", "is", "this"]
    elif case == 3:
        assert isinstance(data, dict), "Extra data must be a dict"
        assert len(data) == 1, "Extra data must be a empty"
        assert data["key"] == "value", "Missing or wrong key-value pair"
        return []
    elif case == 4:
        raise RuntimeError("Sample error that occured during execution")
    else:
        raise ValueError("Unknown test case")


def get_config(cn: str, data) -> Optional[str]:
    if case == 1:
        assert data == None, "Extra data must match"
        return "test"
    elif case == 2:
        assert isinstance(data, dict), "Extra data must be a dict"
        assert len(data) == 0, "Extra data must be a empty"
        return "nice"
    elif case == 3:
        assert isinstance(data, dict), "Extra data must be a dict"
        assert len(data) == 1, "Extra data must be a empty"
        assert data["key"] == "value", "Missing or wrong key-value pair"
        return "try"
    elif case == 4:
        raise RuntimeError("Sample error that occured during execution")
    elif case == 5:
        raise LookupError
    else:
        raise ValueError("Unknown test case")
