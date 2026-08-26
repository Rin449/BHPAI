import os
import sys
import json
import uuid
import hashlib
import shutil
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Security, Depends
from fastapi.responses import JSONResponse
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

try:
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from database.session import async_session
    from database.models import RansomwareSample
    SQLALCHEMY_AVAILABLE = True
except Exception:
    SQLALCHEMY_AVAILABLE = False
    async_session = None

try:
    from redis.asyncio import Redis
    REDIS_AVAILABLE = True
except Exception:
    REDIS_AVAILABLE = False
    Redis = Any

try:
    from celery import Celery
    CELERY_AVAILABLE = True
except Exception:
    CELERY_AVAILABLE = False

from recovery import recovery_engine
from server.vault_router import router as vault_router

logger = logging.getLogger("server.main")
logging.basicConfig(level=logging.INFO)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).resolve().parent / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    API_KEY: Optional[str] = None

    DATABASE_URL: Optional[str] = "postgresql+asyncpg://bhpai:bhpai@localhost:5432/bhpai"
    REDIS_URL: Optional[str] = "redis://localhost:6379/0"
    CELERY_BROKER_URL: Optional[str] = "redis://localhost:6379/1"
    CELERY_BACKEND: Optional[str] = "redis://localhost:6379/2"
    CACHE_TTL_SECONDS: int = 3600

    UPLOAD_DIR: str = str(PROJECT_ROOT / "uploads")
    MAX_UPLOAD_SIZE_MB: int = 50


settings = Settings()

UPLOAD_PATH = Path(settings.UPLOAD_DIR)
UPLOAD_PATH.mkdir(parents=True, exist_ok=True)

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(key: Optional[str] = Security(_api_key_header)) -> None:
    """Dependency that enforces X-API-Key header when API_KEY is configured."""
    configured = settings.API_KEY
    if not configured:
        return
    if not key or key != configured:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key. Supply it via the 'X-API-Key' header.",
        )


app = FastAPI(
    title="BHPAI API",
    version="0.1",
    dependencies=[Depends(verify_api_key)],
)

app.include_router(vault_router)


redis: Redis | None = None

celery_app = None
if CELERY_AVAILABLE:
    celery_app = Celery(__name__, broker=settings.CELERY_BROKER_URL, backend=settings.CELERY_BACKEND)


class MatchRequest(BaseModel):
    sha256: Optional[str] = None
    family_hint: Optional[str] = None
    crypto_fingerprint: Optional[Dict] = None
    features: Optional[Dict] = None


class MatchItem(BaseModel):
    recovery_method: str
    confidence: float


class MatchResponse(BaseModel):
    family: Optional[str] = None
    confidence: float = 0.0
    matches: List[MatchItem] = []


class SampleModel(BaseModel):
    id: str
    sha256: str
    sha1: Optional[str] = None
    md5: Optional[str] = None
    family_id: Optional[str] = None
    variant: Optional[str] = None
    metadata: Optional[Dict] = None


@app.on_event("startup")
async def on_startup():
    global redis
    if REDIS_AVAILABLE:
        try:
            redis = Redis.from_url(
                settings.REDIS_URL,
                decode_responses=True
            )
            await redis.ping()
            logger.info("Connected to Redis")
        except Exception as e:
            logger.warning("Redis unavailable: %s", e)
            redis = None
    else:
        logger.info("redis-py package not installed; Redis cache disabled")


@app.on_event("shutdown")
async def on_shutdown():
    global redis
    if redis is not None:
        try:
            await redis.aclose()
        except Exception:
            try:
                await redis.close()
            except Exception:
                pass


async def get_sample_by_sha256(sha256: str) -> Optional[Dict]:
    if not SQLALCHEMY_AVAILABLE or async_session is None:
        return None
    try:
        async with async_session() as session:
            stmt = select(RansomwareSample).where(RansomwareSample.sha256 == sha256)
            result = await session.execute(stmt)
            sample = result.scalar_one_or_none()
            if not sample:
                return None
            return {
                "id": str(sample.id),
                "sha256": sample.sha256,
                "sha1": sample.sha1,
                "md5": sample.md5,
                "family_id": str(sample.family_id) if sample.family_id else None,
                "variant": sample.variant,
                "metadata": sample.sample_metadata,
            }
    except Exception as e:
        logger.warning("Error fetching sample from DB: %s", e)
        return None


@app.get("  {sha256}", response_model=SampleModel)
async def get_sample(sha256: str):
    cache_key = f"sample:sha256:{sha256}"
    if redis is not None:
        try:
            data = await redis.get(cache_key)
            if data:
                payload = json.loads(data)
                return payload
        except Exception:
            logger.exception("Redis GET failed")

    sample = await get_sample_by_sha256(sha256)
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    if redis is not None:
        try:
            await redis.set(cache_key, json.dumps(sample), ex=settings.CACHE_TTL_SECONDS)
        except Exception:
            logger.exception("Redis SET failed")

    return sample


@app.post("/api/v1/match", response_model=MatchResponse)
async def match(req: MatchRequest):
    cache_key = None
    if req.sha256:
        cache_key = f"match:sha256:{req.sha256}"
        if redis is not None:
            try:
                data = await redis.get(cache_key)
                if data:
                    return MatchResponse.model_validate_json(data) if hasattr(MatchResponse, 'model_validate_json') else MatchResponse.parse_raw(data)
            except Exception:
                logger.exception("Redis GET failed for match cache")

    if req.sha256:
        sample = await get_sample_by_sha256(req.sha256)
        if sample and sample.get("family_id"):
            resp = MatchResponse(
                family=req.family_hint or "KnownFamily",
                confidence=0.99,
                matches=[MatchItem(recovery_method="exact_lookup", confidence=0.99)]
            )
            if cache_key and redis is not None:
                try:
                    raw_data = resp.model_dump_json() if hasattr(resp, 'model_dump_json') else resp.json()
                    await redis.set(cache_key, raw_data, ex=settings.CACHE_TTL_SECONDS)
                except Exception:
                    logger.exception("Redis SET failed for match cache")
            return resp

    engine_results = await recovery_engine.evaluate_all(req)
    
    match_items = [
        MatchItem(recovery_method=item["recovery_method"], confidence=item["confidence"])
        for item in engine_results
    ]

    top_confidence = match_items[0].confidence if match_items else 0.0
    family = req.family_hint if match_items else None

    resp = MatchResponse(
        family=family,
        confidence=top_confidence,
        matches=match_items
    )

    if cache_key is None and req.sha256:
        cache_key = f"match:sha256:{req.sha256}"
    if cache_key and redis is not None:
        try:
            raw_data = resp.model_dump_json() if hasattr(resp, 'model_dump_json') else resp.json()
            await redis.set(cache_key, raw_data, ex=settings.CACHE_TTL_SECONDS)
        except Exception:
            logger.exception("Redis SET failed for match cache")

    return resp



class UploadResponse(BaseModel):
    """Response returned after a successful sample upload."""
    sample_id: str
    sha256: str
    sha1: Optional[str] = None
    md5: Optional[str] = None
    filename: Optional[str] = None
    size_bytes: Optional[int] = None
    family_hint: Optional[str] = None
    method: Optional[str] = None
    stored_path: Optional[str] = None
    already_existed: bool = False
    message: str = "Sample uploaded successfully"


def _hash_bytes(data: bytes) -> Dict[str, str]:
    """Return sha256, sha1, md5 digests for *data*."""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "md5":    hashlib.md5(data).hexdigest(),
    }


async def _save_sample_to_db(
    sample_id: str,
    sha256: str,
    sha1: Optional[str],
    md5: Optional[str],
    family_id: Optional[str],
    variant: Optional[str],
    metadata: Optional[Dict],
) -> bool:
    """Persist a new RansomwareSample row; return True on success."""
    if not SQLALCHEMY_AVAILABLE or async_session is None:
        return False
    try:
        async with async_session() as session:
            from sqlalchemy import select as _select
            stmt = _select(RansomwareSample).where(RansomwareSample.sha256 == sha256)
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()
            if existing:
                return False

            sample = RansomwareSample(
                id=sample_id,
                sha256=sha256,
                sha1=sha1,
                md5=md5,
                family_id=family_id,
                variant=variant,
                sample_metadata=metadata,
            )
            session.add(sample)
            await session.commit()
            return True
    except Exception as exc:
        logger.warning("DB insert failed for upload: %s", exc)
        return False


@app.post("/api/v1/upload", response_model=UploadResponse, summary="Upload a malware sample")
async def upload_sample(
    file: Optional[UploadFile] = File(None, description="Binary sample file (PE, script, archive, …)"),
    sha256: Optional[str] = Form(None, description="Pre-computed SHA-256 hash (required when no file is provided)"),
    sha1: Optional[str] = Form(None, description="Pre-computed SHA-1 hash"),
    md5: Optional[str] = Form(None, description="Pre-computed MD5 hash"),
    family_hint: Optional[str] = Form(None, description="Ransomware family name hint"),
    method: Optional[str] = Form(None, description="Recovery / detection method identifier"),
    variant: Optional[str] = Form(None, description="Variant label within the family"),
    extra_metadata: Optional[str] = Form(None, description="Arbitrary JSON string with extra metadata fields"),
):
    """
    Upload a malware sample to the BHPAI server.

    Accepts **either**:
    - A binary `file` upload (SHA-256/SHA-1/MD5 are computed server-side), **or**
    - A hash-only submission via the `sha256` form field (no file stored on disk).

    Optional form fields
    --------------------
    - `sha256`, `sha1`, `md5`     — pre-computed hashes (used when no file is given, or to
                                     override server-computed values for testing).
    - `family_hint`               — ransomware family name (e.g. ``"LockBit"``)
    - `method`                    — recovery / detection method ID registered in the engine
    - `variant`                   — sub-variant label within the family
    - `extra_metadata`            — arbitrary JSON object merged into the stored metadata
    """
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    file_bytes: Optional[bytes] = None
    original_filename: Optional[str] = None
    computed_hashes: Dict[str, str] = {}

    if file is not None and file.filename:
        file_bytes = await file.read()
        if len(file_bytes) > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum allowed size is {settings.MAX_UPLOAD_SIZE_MB} MB.",
            )
        computed_hashes = _hash_bytes(file_bytes)
        original_filename = file.filename

    final_sha256 = computed_hashes.get("sha256") or sha256
    final_sha1   = computed_hashes.get("sha1")   or sha1
    final_md5    = computed_hashes.get("md5")    or md5

    if not final_sha256:
        raise HTTPException(
            status_code=422,
            detail="Provide either a binary 'file' upload or a 'sha256' form field.",
        )

    if len(final_sha256) != 64:
        raise HTTPException(status_code=422, detail="sha256 must be a 64-character hex string.")

    parsed_meta: Dict[str, Any] = {}
    if extra_metadata:
        try:
            parsed_meta = json.loads(extra_metadata)
            if not isinstance(parsed_meta, dict):
                raise ValueError("extra_metadata must be a JSON object")
        except (json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=f"Invalid extra_metadata JSON: {exc}")

    metadata_payload: Dict[str, Any] = {
        **parsed_meta,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
    }
    if method:
        metadata_payload["method"] = method
    if original_filename:
        metadata_payload["original_filename"] = original_filename

    existing = await get_sample_by_sha256(final_sha256)
    if existing:
        return UploadResponse(
            sample_id=existing["id"],
            sha256=existing["sha256"],
            sha1=existing.get("sha1"),
            md5=existing.get("md5"),
            filename=original_filename,
            size_bytes=len(file_bytes) if file_bytes else None,
            family_hint=family_hint,
            method=method,
            already_existed=True,
            message="Sample already exists in the database.",
        )

    stored_path: Optional[str] = None
    if file_bytes is not None:
        dest = UPLOAD_PATH / final_sha256
        if not dest.exists():
            dest.write_bytes(file_bytes)
        stored_path = str(dest)

    sample_id = str(uuid.uuid4())
    await _save_sample_to_db(
        sample_id=sample_id,
        sha256=final_sha256,
        sha1=final_sha1,
        md5=final_md5,
        family_id=None,
        variant=variant,
        metadata=metadata_payload,
    )

    if redis is not None:
        for prefix in ("sample:sha256:", "match:sha256:"):
            try:
                await redis.delete(f"{prefix}{final_sha256}")
            except Exception:
                pass

    logger.info(
        "Sample uploaded: sha256=%s filename=%s size=%s method=%s",
        final_sha256, original_filename, len(file_bytes) if file_bytes else "(hash-only)", method,
    )

    return UploadResponse(
        sample_id=sample_id,
        sha256=final_sha256,
        sha1=final_sha1,
        md5=final_md5,
        filename=original_filename,
        size_bytes=len(file_bytes) if file_bytes else None,
        family_hint=family_hint,
        method=method,
        stored_path=stored_path,
        already_existed=False,
        message="Sample uploaded successfully.",
    )


@app.post("/api/v1/recovery/{sample_id}/attempt")
async def attempt_recovery(sample_id: str, method: Optional[str] = None):
    rec_method = recovery_engine.get_method(method) if method else None
    if rec_method:
        logger.info("Executing recovery method %s for sample %s", method, sample_id)
        result = await rec_method.recover({"sample_id": sample_id})
        return {"task_id": None, "status": "executed", "result": result}

    payload = {"sample_id": sample_id, "method": method}
    if CELERY_AVAILABLE and celery_app is not None:
        try:
            task = celery_app.send_task("bhpai.tasks.attempt_recovery", args=[payload], kwargs={})
            return {"task_id": task.id, "status": "enqueued"}
        except Exception:
            logger.exception("Failed to enqueue Celery task")
            raise HTTPException(status_code=500, detail="Failed to enqueue job")

    logger.info("Recovery attempt (stub) for %s using %s", sample_id, method)
    return {"task_id": None, "status": "stub-executed", "result": {"success": False, "reason": "Celery not configured and method not found"}}

if __name__ == "__main__":
    module_str = "main:app" if Path.cwd() == Path(__file__).parent else "server.main:app"
    uvicorn.run(module_str, host="0.0.0.0", port=8000, reload=True)
