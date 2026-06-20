import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import health, auth, passwords
from app.core.config import settings
from app.core.exceptions import (
    ServiceUnavailableError,
    HIBPError,
    AIServiceError,
    service_unavailable_handler,
    hibp_error_handler,
    ai_error_handler,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("sparkgate")

app = FastAPI(
    title="SparkGate API",
    description="AI-assisted password evaluation and generation",
    version="1.0.0",
)

raw_origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
exact_origins = [o for o in raw_origins if "*" not in o]
regex_origins = [o.replace("*", ".*") for o in raw_origins if "*" in o]

app.add_middleware(
    CORSMiddleware,
    allow_origins=exact_origins or None,
    allow_origin_regex="|".join(regex_origins) if regex_origins else None,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(passwords.router)

app.add_exception_handler(ServiceUnavailableError, service_unavailable_handler)
app.add_exception_handler(HIBPError, hibp_error_handler)
app.add_exception_handler(AIServiceError, ai_error_handler)

logger.info("SparkGate API started — env=%s", settings.env)
