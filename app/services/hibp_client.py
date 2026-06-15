import hashlib
import logging

import httpx

from app.core.config import settings

logger = logging.getLogger("sparkgate.hibp")


async def check_password(password: str) -> tuple[bool, int]:
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    async with httpx.AsyncClient() as client:
        logger.debug("HIBP request: prefix=%s", prefix)
        response = await client.get(
            f"{settings.hibp_api_url}/range/{prefix}",
            headers={"Add-Padding": "true"},
        )
        response.raise_for_status()

    for line in response.text.splitlines():
        line_suffix, count = line.split(":")
        if line_suffix.strip() == suffix:
            logger.info("HIBP match found: pwned_count=%s", count)
            return True, int(count)

    logger.debug("HIBP: no match found")
    return False, 0
