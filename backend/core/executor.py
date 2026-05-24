"""
Attack executor — orchestrates all attack classes against a profiled target.
Runs attacks in priority order, adapts based on what the profiler found,
and collects all results into a structured scan report.
"""
import asyncio
from dataclasses import dataclass, field
from enum import Enum

from attacks.base import AttackResult, AttackStatus, TargetProfile
from attacks.prompt_injection import DirectPromptInjection
from attacks.jailbreaks import JailbreakAttack
from attacks.data_extraction import DataExtractionAttack
from attacks.agent_hijack import AgentHijackAttack


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class ScanResult:
    scan_id: str
    target_endpoint: str
    status: ScanStatus
    profile: TargetProfile | None = None
    findings: list[AttackResult] = field(default_factory=list)
    # Attacks that errored — not vulnerabilities, but worth knowing
    errors: list[AttackResult] = field(default_factory=list)
    total_attacks_run: int = 0
    duration_ms: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity and f.severity.value == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity and f.severity.value == "high")

    @property
    def is_vulnerable(self) -> bool:
        return len(self.findings) > 0

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target_endpoint": self.target_endpoint,
            "status": self.status.value,
            "is_vulnerable": self.is_vulnerable,
            "total_attacks_run": self.total_attacks_run,
            "duration_ms": self.duration_ms,
            "findings_count": len(self.findings),
            "critical": self.critical_count,
            "high": self.high_count,
            "profile": {
                "model_family": self.profile.model_family if self.profile else "unknown",
                "framework": self.profile.framework if self.profile else "unknown",
                "has_tools": self.profile.has_tools if self.profile else False,
                "has_rag": self.profile.has_rag if self.profile else False,
            },
            "findings": [
                {
                    "attack_class": f.attack_class,
                    "title": f.title,
                    "severity": f.severity.value if f.severity else None,
                    "description": f.description,
                    "proof_of_concept": f.proof_of_concept,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "duration_ms": f.duration_ms,
                }
                for f in self.findings
            ],
        }


async def run_scan(scan_id: str, profile: TargetProfile) -> ScanResult:
    """
    Execute all appropriate attacks against the target.
    Attack selection is driven by the profile — agent-specific attacks
    only run if the profiler detected tool/agent capabilities.
    """
    import time
    start = time.monotonic()

    result = ScanResult(
        scan_id=scan_id,
        target_endpoint=profile.endpoint,
        status=ScanStatus.RUNNING,
        profile=profile,
    )

    # Always run these — every AI system is a target for these
    core_attacks = [
        DirectPromptInjection(profile),
        JailbreakAttack(profile),
        DataExtractionAttack(profile),
    ]

    # Only run agent-specific attacks if the target looks like an agent
    agent_attacks = []
    if profile.has_tools or profile.framework in ("langchain", "autogen", "crewai"):
        agent_attacks.append(AgentHijackAttack(profile))

    all_attacks = core_attacks + agent_attacks

    # Run all attacks concurrently — they're independent
    attack_results = await asyncio.gather(
        *[attack.run() for attack in all_attacks],
        return_exceptions=False,
    )

    for attack_result in attack_results:
        result.total_attacks_run += 1
        if attack_result.status == AttackStatus.VULNERABLE:
            result.findings.append(attack_result)
        elif attack_result.status == AttackStatus.ERROR:
            result.errors.append(attack_result)

    # Sort findings by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    result.findings.sort(
        key=lambda f: severity_order.get(f.severity.value if f.severity else "info", 99)
    )

    result.status = ScanStatus.COMPLETE
    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result
