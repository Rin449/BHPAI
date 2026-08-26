from __future__ import annotations
import enum
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

class CandidateStatus(str, enum.Enum):
    KEY_CANDIDATE = "KEY_CANDIDATE"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"

@dataclass
class CryptoObject:
    object_id: int
    origin: str = "UNKNOWN"
    size_bytes: int = 0
    buffer_addr: int = 0
    buffer_data: str = ""
    raw_bytes_hex: str = ""
    region_protection: str = "PAGE_READWRITE"
    consumed_by: str = "UNKNOWN"
    algorithm: str = "UNKNOWN"
    status: CandidateStatus = CandidateStatus.KEY_CANDIDATE
    timestamp_first_seen: int = 0
    timestamp_last_seen: int = 0
    confidence: float = 0.0
    evidence_ids: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "object_id": self.object_id,
            "origin": self.origin,
            "size_bytes": self.size_bytes,
            "buffer_addr": self.buffer_addr,
            "buffer_data": self.buffer_data,
            "raw_bytes_hex": self.raw_bytes_hex,
            "region_protection": self.region_protection,
            "consumed_by": self.consumed_by,
            "algorithm": self.algorithm,
            "status": self.status.value,
            "timestamp_first_seen": self.timestamp_first_seen,
            "timestamp_last_seen": self.timestamp_last_seen,
            "confidence": self.confidence,
            "evidence_ids": self.evidence_ids,
        }

@dataclass
class KeyCandidate:
    candidate_id: int
    source_object_id: int
    algorithm: str = "UNKNOWN"
    size: int = 0
    status: CandidateStatus = CandidateStatus.KEY_CANDIDATE
    confidence: float = 0.0
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "source_object_id": self.source_object_id,
            "algorithm": self.algorithm,
            "size": self.size,
            "status": self.status.value,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }

class CandidatePool:
    def __init__(self):
        self.candidates: List[KeyCandidate] = []

    def add(self, candidate: KeyCandidate) -> None:
        self.candidates.append(candidate)

    def correlate(self, objects: List[CryptoObject]) -> None:
        for obj in objects:
            existing = next((c for c in self.candidates if c.source_object_id == obj.object_id), None)
            if existing:
                existing.algorithm = obj.algorithm
                existing.size = obj.size_bytes
                existing.status = obj.status
                existing.confidence = obj.confidence
            else:
                cand = KeyCandidate(
                    candidate_id=len(self.candidates) + 1,
                    source_object_id=obj.object_id,
                    algorithm=obj.algorithm,
                    size=obj.size_bytes,
                    status=obj.status,
                    confidence=obj.confidence,
                    evidence=f"Origin: {obj.origin} -> Consumed: {obj.consumed_by}",
                )
                self.candidates.append(cand)
        self.rank()

    def rank(self) -> None:
        def sort_key(c: KeyCandidate):
            status_order = {
                CandidateStatus.VALIDATED: 0,
                CandidateStatus.KEY_CANDIDATE: 1,
                CandidateStatus.EXPIRED: 2,
                CandidateStatus.REJECTED: 3,
            }
            return (status_order.get(c.status, 4), -c.confidence)

        self.candidates.sort(key=sort_key)

    def expire(self, current_timestamp: int, ttl: int) -> None:
        for cand in self.candidates:
            if cand.status == CandidateStatus.KEY_CANDIDATE and ttl > 0 and current_timestamp > ttl:
                cand.status = CandidateStatus.EXPIRED

    def get_validated(self) -> List[KeyCandidate]:
        return [c for c in self.candidates if c.status == CandidateStatus.VALIDATED]

    def to_list(self) -> List[Dict[str, Any]]:
        return [c.to_dict() for c in self.candidates]

class CandidateValidator:
    @classmethod
    def validate(
        cls,
        obj: CryptoObject,
        events: List[Dict[str, Any]],
        pool: Optional[CandidatePool] = None,
    ) -> CandidateStatus:
        if (
            not cls.structural_check(obj)
            or not cls.size_check(obj)
            or not cls.algorithm_consistency(obj)
            or not cls.producer_consumer_consistency(obj)
            or not cls.temporal_consistency(obj)
        ):
            return CandidateStatus.REJECTED

        if cls.test_vector_validation(obj):
            return CandidateStatus.VALIDATED

        return CandidateStatus.KEY_CANDIDATE

    @classmethod
    def structural_check(cls, obj: CryptoObject) -> bool:
        return bool(obj.origin and obj.origin != "UNKNOWN" and obj.size_bytes > 0)

    @classmethod
    def size_check(cls, obj: CryptoObject) -> bool:
        valid_sizes = {12, 16, 24, 32, 64, 128, 256, 512}
        return obj.size_bytes in valid_sizes

    @classmethod
    def algorithm_consistency(cls, obj: CryptoObject) -> bool:
        if obj.algorithm == "AES-256" and obj.size_bytes not in (32, 0):
            return False
        if obj.algorithm == "AES-128" and obj.size_bytes not in (16, 0):
            return False
        return True

    @classmethod
    def producer_consumer_consistency(cls, obj: CryptoObject) -> bool:
        if "Process Memory Snapshot" in obj.origin:
            return False
        valid_flows = [
            ("BCryptGenRandom", "BCryptGenerateSymmetricKey"),
            ("BCryptGenRandom", "BCryptEncrypt"),
            ("BCryptGenerateSymmetricKey", "BCryptEncrypt"),
            ("CryptGenRandom", "CryptEncrypt"),
            ("CryptGenKey", "CryptEncrypt"),
        ]
        if (obj.origin, obj.consumed_by) in valid_flows:
            return True
        return bool(obj.origin and obj.origin != "UNKNOWN")

    @classmethod
    def temporal_consistency(cls, obj: CryptoObject) -> bool:
        if obj.timestamp_first_seen > 0 and obj.timestamp_last_seen > 0:
            return obj.timestamp_first_seen <= obj.timestamp_last_seen
        return True

    @classmethod
    def test_vector_validation(cls, obj: CryptoObject) -> bool:
        if "Process Memory Snapshot" in obj.origin:
            return False
        return bool(obj.confidence >= 0.90 and obj.evidence_ids and obj.status != CandidateStatus.REJECTED)

class CryptoDataflowTracker:
    def __init__(self):
        self.objects: List[CryptoObject] = []
        self.pool: CandidatePool = CandidatePool()

    def process_events(self, events: List[Dict[str, Any]]) -> Tuple[List[CryptoObject], CandidatePool]:
        self.objects.clear()
        addr_to_events: Dict[int, List[Tuple[int, Dict[str, Any]]]] = {}

        for idx, ev in enumerate(events):
            ev_id = ev.get("event_id", idx + 1)
            src_addr = ev.get("source_buffer_addr") or ev.get("buffer") or 0
            dest_addr = ev.get("dest_buffer_addr") or 0

            if isinstance(src_addr, str) and src_addr.startswith("0x"):
                src_addr = int(src_addr, 16)
            if isinstance(dest_addr, str) and dest_addr.startswith("0x"):
                dest_addr = int(dest_addr, 16)

            if src_addr:
                addr_to_events.setdefault(int(src_addr), []).append((ev_id, ev))
            if dest_addr and dest_addr != src_addr:
                addr_to_events.setdefault(int(dest_addr), []).append((ev_id, ev))

        obj_counter = 1
        for addr, event_tuples in addr_to_events.items():
            ev_ids = [t[0] for t in event_tuples]
            ev_list = [t[1] for t in event_tuples]

            producer = "UNKNOWN"
            consumer = "UNKNOWN"
            size = 0
            algorithm = "UNKNOWN"
            raw_bytes_hex = ""
            timestamps = [ev.get("timestamp", 0) for ev in ev_list if ev.get("timestamp")]

            for ev in ev_list:
                api = ev.get("api_name") or ev.get("api") or ""
                lower_api = api.lower()

                if "genrandom" in lower_api or "genkey" in lower_api:
                    producer = api
                    size = ev.get("output_size") or ev.get("size") or size
                elif "generatesymmetrickey" in lower_api or "derivekey" in lower_api or "importkey" in lower_api:
                    if producer == "UNKNOWN":
                        producer = api
                    else:
                        consumer = api
                    key_bits = ev.get("key_size_bits") or ev.get("key_size") or 0
                    if key_bits:
                        size = key_bits // 8 if key_bits > 64 else key_bits
                elif "encrypt" in lower_api:
                    consumer = api

                hint = ev.get("algorithm_hint") or ev.get("algorithm")
                if hint and hint != "AES":
                    algorithm = hint

                if ev.get("raw_bytes_hex"):
                    raw_bytes_hex = ev.get("raw_bytes_hex")

            if size == 0:
                size = 32
            if algorithm == "UNKNOWN" and producer != "UNKNOWN":
                algorithm = "AES-256" if size == 32 else ("AES-128" if size == 16 else "UNKNOWN")

            buf_str = f"0x{addr:x}_len{size}"

            obj = CryptoObject(
                object_id=obj_counter,
                origin=producer,
                size_bytes=size,
                buffer_addr=addr,
                buffer_data=buf_str,
                raw_bytes_hex=raw_bytes_hex,
                region_protection="PAGE_READWRITE",
                consumed_by=consumer,
                algorithm=algorithm,
                timestamp_first_seen=timestamps[0] if timestamps else 0,
                timestamp_last_seen=timestamps[-1] if timestamps else 0,
                confidence=min(0.70 + (len(ev_ids) * 0.10), 0.95) if producer != "UNKNOWN" else 0.30,
                evidence_ids=ev_ids,
            )
            obj_counter += 1

            obj.status = CandidateValidator.validate(obj, ev_list, self.pool)
            self.objects.append(obj)

        self.pool.correlate(self.objects)
        return self.objects, self.pool
