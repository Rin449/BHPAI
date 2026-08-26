from recovery.base import RecoveryMethod
from recovery.registry import RecoveryEngineRegistry, recovery_engine
from recovery.methods import Method001, ExactLookupMethod

recovery_engine.register(Method001())
recovery_engine.register(ExactLookupMethod())

__all__ = [
    "RecoveryMethod",
    "RecoveryEngineRegistry",
    "recovery_engine",
    "Method001",
    "ExactLookupMethod",
]
