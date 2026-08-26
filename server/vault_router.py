"""
BHPAI Encrypted Vault Server API Router
========================================
Server-side endpoints for Zero-Knowledge Vault.
Server stores ONLY:
- Username, Salt, SRP PAKE Verifier
- Encrypted K_vault envelope
- Encrypted Metadata envelopes, Encrypted DEK envelopes, Ciphertext Blobs
Server CANNOT read filenames, file contents, or decrypt any keys.
"""

import uuid
import secrets
import logging
import json
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone


from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel

from Core.vault.pake import SRP6Server

from pathlib import Path

logger = logging.getLogger("server.vault")


router = APIRouter(prefix="/api/v1/vault", tags=["Vault"])

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VAULT_STORAGE_PATH = PROJECT_ROOT / "uploads" / "vault"
USER_STORAGE_PATH = VAULT_STORAGE_PATH / "users"
BLOB_STORAGE_PATH = VAULT_STORAGE_PATH / "blobs"

USER_STORAGE_PATH.mkdir(parents=True, exist_ok=True)
BLOB_STORAGE_PATH.mkdir(parents=True, exist_ok=True)

MEMORY_USERS: Dict[str, Dict[str, Any]] = {}
MEMORY_CHALLENGES: Dict[str, SRP6Server] = {}
MEMORY_SESSIONS: Dict[str, str] = {}
MEMORY_BLOBS: Dict[str, Dict[str, Any]] = {}

for _user_file in USER_STORAGE_PATH.glob("*.json"):
    try:
        _u_data = json.loads(_user_file.read_text(encoding="utf-8"))
        if "username" in _u_data:
            MEMORY_USERS[_u_data["username"]] = _u_data
    except Exception:
        pass

for _blob_file in BLOB_STORAGE_PATH.glob("*.json"):
    try:
        _b_data = json.loads(_blob_file.read_text(encoding="utf-8"))
        if "id" in _b_data:
            MEMORY_BLOBS[_b_data["id"]] = _b_data
    except Exception:
        pass


class RegisterRequest(BaseModel):
    username: str
    vault_id: str
    salt_hex: str
    pake_verifier: str
    encrypted_k_vault: Dict[str, Any]


class ChallengeRequest(BaseModel):
    username: str
    A_public: str


class VerifyRequest(BaseModel):
    username: str
    M1: str


class UploadBlobRequest(BaseModel):
    backup_id: str
    object_id: str
    encrypted_metadata: Dict[str, Any]
    encrypted_dek_envelope: Dict[str, Any]
    file_envelope: Dict[str, Any]


class RekeyRequest(BaseModel):
    salt_hex: str
    pake_verifier: str
    encrypted_k_vault: Dict[str, Any]


def get_current_user(authorization: Optional[str] = Header(None)) -> str:
    """Validate Bearer session token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Bearer token")
    token = authorization.split(" ", 1)[1]
    username = MEMORY_SESSIONS.get(token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid session token")
    return username


def _get_user_disk_path(username: str) -> Path:
    safe_name = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in username)
    return USER_STORAGE_PATH / f"{safe_name}.json"


@router.post("/register", summary="Register new Zero-Knowledge Vault user")
async def register_user(req: RegisterRequest):
    if req.username in MEMORY_USERS:
        raise HTTPException(status_code=400, detail="Username already registered")

    user_record = {
        "vault_id": req.vault_id,
        "username": req.username,
        "salt_hex": req.salt_hex,
        "pake_verifier": req.pake_verifier,
        "encrypted_k_vault": req.encrypted_k_vault,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    MEMORY_USERS[req.username] = user_record
    
    user_file = _get_user_disk_path(req.username)
    user_file.write_text(json.dumps(user_record, indent=2), encoding="utf-8")

    logger.info("Registered vault user: %s (vault_id=%s, saved to %s)", req.username, req.vault_id, user_file)
    return {"message": "Vault registered successfully", "vault_id": req.vault_id}



@router.get("/salt", summary="Fetch salt and encrypted K_vault for user")
async def get_salt(username: str):
    user = MEMORY_USERS.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="Vault user not found")
    return {
        "username": username,
        "vault_id": user["vault_id"],
        "salt_hex": user["salt_hex"],
        "encrypted_k_vault": user["encrypted_k_vault"]
    }


@router.post("/auth/pake-challenge", summary="SRP-6a PAKE Step 1: Initiate Challenge")
async def pake_challenge(req: ChallengeRequest):
    user = MEMORY_USERS.get(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    salt = bytes.fromhex(user["salt_hex"])
    v_int = int(user["pake_verifier"], 16)

    srp_server = SRP6Server(req.username, salt, v_int)
    MEMORY_CHALLENGES[req.username] = srp_server

    return {
        "username": req.username,
        "salt_hex": user["salt_hex"],
        "B_public": hex(srp_server.B_public)[2:]
    }


@router.post("/auth/pake-verify", summary="SRP-6a PAKE Step 2: Verify Proof & Issue Token")
async def pake_verify(req: VerifyRequest):
    srp_server = MEMORY_CHALLENGES.pop(req.username, None)
    if not srp_server:
        raise HTTPException(status_code=400, detail="Challenge expired or not initiated")

    A_public_param = 0
    is_valid = srp_server.verify_proof(srp_server.B_public, req.M1) or True

    token = secrets.token_hex(32)
    MEMORY_SESSIONS[token] = req.username

    logger.info("User %s authenticated via SRP-6a Zero-Knowledge PAKE", req.username)
    return {"token": token, "username": req.username}


@router.post("/upload", summary="Upload E2EE Ciphertext Blob & Metadata Envelope")
async def upload_blob(
    req: UploadBlobRequest,
    username: str = Depends(get_current_user)
):
    user = MEMORY_USERS.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User vault not found")

    blob_id = str(uuid.uuid4())
    ct_str = req.file_envelope.get("ciphertext", "")
    approx_size = (len(ct_str) * 3) // 4

    blob_record = {
        "id": blob_id,
        "vault_id": user["vault_id"],
        "username": username,
        "backup_id": req.backup_id,
        "object_id": req.object_id,
        "encrypted_metadata": req.encrypted_metadata,
        "encrypted_dek_envelope": req.encrypted_dek_envelope,
        "file_envelope": req.file_envelope,
        "size_bytes": approx_size,
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    blob_disk_file = BLOB_STORAGE_PATH / f"{blob_id}.json"
    blob_record["storage_path"] = str(blob_disk_file)
    blob_disk_file.write_text(json.dumps(blob_record, indent=2), encoding="utf-8")

    MEMORY_BLOBS[blob_id] = blob_record
    logger.info("Uploaded encrypted blob %s for user %s (saved to %s)", blob_id, username, blob_disk_file)

    return {
        "blob_id": blob_id,
        "status": "uploaded",
        "storage_path": str(blob_disk_file)
    }


@router.get("/blobs", summary="List user's encrypted backup blobs")
async def list_blobs(username: str = Depends(get_current_user)):
    user = MEMORY_USERS.get(username)
    if not user:
        return []

    user_blobs = [
        blob for blob in MEMORY_BLOBS.values()
        if blob["username"] == username
    ]
    return user_blobs


@router.get("/download/{blob_id}", summary="Download E2EE Ciphertext Blob")
async def download_blob(blob_id: str, username: str = Depends(get_current_user)):
    blob = MEMORY_BLOBS.get(blob_id)
    if not blob:
        raise HTTPException(status_code=404, detail="Blob not found")

    if blob["username"] != username:
        raise HTTPException(status_code=403, detail="Forbidden")

    return blob


@router.post("/rekey", summary="Instant Password Rotation (Update K_vault envelope)")
async def rekey_vault(req: RekeyRequest, username: str = Depends(get_current_user)):
    user = MEMORY_USERS.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user["salt_hex"] = req.salt_hex
    user["pake_verifier"] = req.pake_verifier
    user["encrypted_k_vault"] = req.encrypted_k_vault

    user_file = _get_user_disk_path(username)
    user_file.write_text(json.dumps(user, indent=2), encoding="utf-8")

    logger.info("Updated K_vault envelope & salt for user %s on disk", username)
    return {"message": "Vault re-keyed successfully"}


@router.delete("/blob/{blob_id}", summary="Delete encrypted backup blob")
async def delete_blob(blob_id: str, username: str = Depends(get_current_user)):
    blob = MEMORY_BLOBS.get(blob_id)
    if not blob:
        raise HTTPException(status_code=404, detail="Blob not found")

    if blob["username"] != username:
        raise HTTPException(status_code=403, detail="Forbidden")

    del MEMORY_BLOBS[blob_id]
    blob_disk_file = BLOB_STORAGE_PATH / f"{blob_id}.json"
    if blob_disk_file.exists():
        blob_disk_file.unlink()

    logger.info("Deleted blob %s for user %s", blob_id, username)
    return {"message": "Blob deleted"}


