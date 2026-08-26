from abc import ABC, abstractmethod
from typing import Any, Dict

class RecoveryMethod(ABC):
    method_id: str
    name: str
    version: str

    @abstractmethod
    async def match(self, sample: Any) -> float:
        """
        Evaluate confidence score (0.0 to 1.0) of this recovery method for the given sample.
        """
        pass

    @abstractmethod
    async def recover(self, sample: Any) -> Dict[str, Any]:
        """
        Execute recovery algorithm for the given sample.
        """
        pass
