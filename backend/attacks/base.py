from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import time


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    ERROR = "error"


@dataclass
class AttackResult:
    attack_id: str
    attack_class: str
    status: AttackStatus
    severity: Severity | None = None
    title: str = ""
    description: str = ""
    # The exact payload that triggered the vulnerability
    proof_of_concept: str = ""
    # Raw response from the target that confirms the vulnerability
    evidence: str = ""
    remediation: str = ""
    duration_ms: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TargetProfile:
    endpoint: str
    # Detected model family: gpt, claude, gemini, llama, unknown
    model_family: str = "unknown"
    # Detected framework: langchain, llamaindex, custom, unknown
    framework: str = "unknown"
    # Whether the target has a visible system prompt
    has_system_prompt: bool = False
    # Whether the target uses RAG/tool calling
    has_tools: bool = False
    has_rag: bool = False
    # HTTP headers needed for the target API
    headers: dict[str, str] = field(default_factory=dict)
    # Field name the target expects for user messages
    input_field: str = "message"
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseAttack(ABC):
    """
    Every attack implements this interface. The executor calls them uniformly
    without knowing the internals of each attack class.
    """

    severity: Severity = Severity.MEDIUM
    attack_class: str = "base"

    def __init__(self, target: TargetProfile):
        self.target = target

    @abstractmethod
    async def execute(self) -> AttackResult:
        """Run the attack. Return a result regardless of outcome — never raise."""
        ...

    async def run(self) -> AttackResult:
        start = time.monotonic()
        try:
            result = await self.execute()
        except Exception as exc:
            result = AttackResult(
                attack_id=self._attack_id(),
                attack_class=self.attack_class,
                status=AttackStatus.ERROR,
                metadata={"error": str(exc)},
            )
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    def _attack_id(self) -> str:
        import uuid
        return str(uuid.uuid4())

    def _make_result(
        self,
        status: AttackStatus,
        *,
        title: str = "",
        description: str = "",
        poc: str = "",
        evidence: str = "",
        remediation: str = "",
        metadata: dict | None = None,
    ) -> AttackResult:
        return AttackResult(
            attack_id=self._attack_id(),
            attack_class=self.attack_class,
            status=status,
            severity=self.severity if status == AttackStatus.VULNERABLE else None,
            title=title,
            description=description,
            proof_of_concept=poc,
            evidence=evidence,
            remediation=remediation,
            metadata=metadata or {},
        )
