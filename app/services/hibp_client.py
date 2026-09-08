import hashlib
import logging

import httpx

from app.core.config import settings
from app.services.cache import hibp_cache

logger = logging.getLogger("sparkgate.hibp")

KEY_HIBP = "hibp"


def _suffixes_from_response(text: str) -> dict[str, int]:
    suffixes = {}
    for line in text.splitlines():
        line_suffix, count = line.split(":")
        suffixes[line_suffix.strip()] = int(count)
    return suffixes


async def check_password(password: str) -> tuple[bool, int]:
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    suffixes = hibp_cache.get((KEY_HIBP, prefix))
    if suffixes is not None:
        logger.debug("HIBP cache hit: prefix=%s", prefix)
        found = suffixes.get(suffix, 0)
        return (found > 0, found)

    async with httpx.AsyncClient() as client:
        logger.debug("HIBP request: prefix=%s", prefix)
        response = await client.get(
            f"{settings.hibp_api_url}/range/{prefix}",
            headers={"Add-Padding": "true"},
        )
        response.raise_for_status()

    suffixes = _suffixes_from_response(response.text)
    hibp_cache.set((KEY_HIBP, prefix), suffixes)

    found = suffixes.get(suffix, 0)
    if found:
        logger.info("HIBP match found: pwned_count=%s", found)
    else:
        logger.debug("HIBP: no match found")
    return (found > 0, found)
