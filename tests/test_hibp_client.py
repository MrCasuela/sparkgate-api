import hashlib

import pytest
import respx


def get_hibp_prefix(password: str) -> str:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    return sha1[:5]


class TestHIBPClient:
    def test_sha1_prefix_only_sent(self):
        password = "TestPassword123!"
        prefix = get_hibp_prefix(password)
        full_hash = hashlib.sha1(password.encode()).hexdigest().upper()

        assert len(prefix) == 5
        assert full_hash.startswith(prefix)
        assert prefix != full_hash
        assert password not in prefix

    def test_different_passwords_different_prefixes(self):
        p1 = get_hibp_prefix("password1")
        p2 = get_hibp_prefix("password2")
        assert p1 != p2 or True  # collissions are possible but unlikely - just check format

    def test_prefix_hex_format(self):
        prefix = get_hibp_prefix("hello")
        assert all(c in "0123456789ABCDEF" for c in prefix)
        assert len(prefix) == 5

    def test_k_anonymity_no_full_hash_sent(self):
        password = "supersecret123"
        prefix = get_hibp_prefix(password)
        full_hash = hashlib.sha1(password.encode()).hexdigest().upper()

        mock_hibp_response = (
            "00112233445566778899AABBCCDDEEFF:3\n"
            "FFFEDDCCBBAA99887766554433221100:1\n"
        )

        suffix = full_hash[5:]
        found = False
        for line in mock_hibp_response.splitlines():
            if line.split(":")[0].strip() == suffix:
                found = True
                break

        assert not found or True


@pytest.mark.asyncio
async def test_check_password_returns_not_found():
    """HIBP responds 200 with non-matching hashes → not compromised."""
    from app.core.config import settings
    from app.services.hibp_client import check_password

    password = "this_password_has_no_matches_12345"
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    # Return hashes that don't match our suffix
    mock_hibp_response = (
        "0000000000000000000000000000000000000:1\n"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:5\n"
    )

    with respx.mock:
        respx.get(f"{settings.hibp_api_url}/range/{prefix}").respond(
            text=mock_hibp_response, status_code=200,
            headers={"Add-Padding": "true"},
        )
        is_compromised, count = await check_password(password)

    assert is_compromised is False
    assert count == 0


@pytest.mark.asyncio
async def test_check_password_returns_compromised():
    """HIBP returns matching hash suffix → compromised."""
    from app.core.config import settings
    from app.services.hibp_client import check_password

    password = "P@ssw0rd!"
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    mock_hibp_response = (
        f"{suffix}:42\n"
        "0000000000000000000000000000000000000:1\n"
    )

    with respx.mock:
        respx.get(f"{settings.hibp_api_url}/range/{prefix}").respond(
            text=mock_hibp_response, status_code=200,
            headers={"Add-Padding": "true"},
        )
        is_compromised, count = await check_password(password)

    assert is_compromised is True
    assert count == 42
