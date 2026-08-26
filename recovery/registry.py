import logging
from typing import Dict, List, Optional, Any
from recovery.base import RecoveryMethod

logger = logging.getLogger("recovery.registry")

class RecoveryEngineRegistry:
    def __init__(self):
        self._methods: Dict[str, RecoveryMethod] = {}

    def register(self, method: RecoveryMethod) -> None:
        if not hasattr(method, "method_id") or not method.method_id:
            raise ValueError("RecoveryMethod must define a valid method_id")
        self._methods[method.method_id] = method
        logger.info("Registered recovery method: %s (%s - v%s)", method.method_id, method.name, getattr(method, 'version', '1.0'))

    def get_method(self, method_id: str) -> Optional[RecoveryMethod]:
        return self._methods.get(method_id)

    def list_methods(self) -> List[RecoveryMethod]:
        return list(self._methods.values())

    async def evaluate_all(self, sample: Any) -> List[Dict[str, Any]]:
        matches = []
        events = None
        if isinstance(sample, dict):
            events = sample.get("events") or sample.get("crypto_events")
        elif hasattr(sample, "events"):
            events = getattr(sample, "events")

        tracker_result = None
        if events and isinstance(events, list):
            try:
                from recovery.crypto_tracker import CryptoDataflowTracker
                tracker = CryptoDataflowTracker()
                objects, pool = tracker.process_events(events)
                tracker_result = {
                    "crypto_objects": [obj.to_dict() for obj in objects],
                    "candidate_pool": pool.to_list(),
                    "validated_candidates": [c.to_dict() for c in pool.get_validated()]
                }
            except Exception as tr_err:
                logger.warning("Error running CryptoDataflowTracker: %s", tr_err)

        for method_id, method in self._methods.items():
            try:
                confidence = await method.match(sample)
                if confidence > 0.0:
                    entry = {
                        "recovery_method": method_id,
                        "name": method.name,
                        "version": getattr(method, 'version', '1.0'),
                        "confidence": float(confidence),
                    }
                    if tracker_result:
                        entry["tracker_analysis"] = tracker_result
                    matches.append(entry)
            except Exception as e:
                logger.error("Error evaluating method %s: %s", method_id, e, exc_info=True)

        matches.sort(key=lambda x: x["confidence"], reverse=True)
        return matches

recovery_engine = RecoveryEngineRegistry()
