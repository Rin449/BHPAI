from typing import Any, Dict
from recovery.base import RecoveryMethod

class ExactLookupMethod(RecoveryMethod):
    method_id = "exact_lookup"
    name = "Exact Database SHA256 Lookup"
    version = "1.0"

    async def match(self, sample: Any) -> float:
        sha256 = getattr(sample, "sha256", None) if hasattr(sample, "sha256") else None
        if sha256 is None and isinstance(sample, dict):
            sha256 = sample.get("sha256")

        family_hint = getattr(sample, "family_hint", None) if hasattr(sample, "family_hint") else None
        if family_hint is None and isinstance(sample, dict):
            family_hint = sample.get("family_hint")

        if sha256 or family_hint:
            return 0.99
        return 0.0

    async def recover(self, sample: Any) -> Dict[str, Any]:
        return {
            "status": "success",
            "method": self.method_id,
            "message": "Direct table match lookup recovery",
        }
