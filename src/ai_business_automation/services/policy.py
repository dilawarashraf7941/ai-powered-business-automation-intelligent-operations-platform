"""Pure deterministic policy evaluation and timestamp attachment."""

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ai_business_automation.models import (
    DEFAULT_CONFIDENCE_THRESHOLD,
    POLICY_VERSION,
    BusinessIntelligenceResult,
    CanonicalBusinessEvent,
    DecisionOutcome,
    EvidenceCode,
    EvidenceSource,
    Intent,
    PolicyDecision,
    PolicyEvidence,
    Priority,
    RecommendedAction,
    RecommendedNextStep,
    RiskLevel,
    Urgency,
)
from ai_business_automation.services.classification import EventClassifier

_LOGGER = logging.getLogger("ai_business_automation.policy")

_REVIEW_ACTIONS = frozenset(
    {
        RecommendedAction.CONTACT_HUMAN,
        RecommendedAction.REQUEST_INFORMATION,
        RecommendedAction.ESCALATE,
        RecommendedAction.SCHEDULE_CONSULTATION,
        RecommendedAction.NURTURE,
    }
)


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    """Deterministic result before non-decision metadata is attached."""

    decision: DecisionOutcome
    action: RecommendedAction
    risk: RiskLevel
    evidence: tuple[PolicyEvidence, ...]


@dataclass(frozen=True, slots=True)
class DeterministicPolicyEngine:
    """Pure closed-world policy version 1.0 with fail-closed precedence."""

    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    classifier: EventClassifier = field(default_factory=EventClassifier)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence_threshold <= 1.0:
            raise ValueError("confidence threshold must be between zero and one")

    def evaluate(
        self,
        event: CanonicalBusinessEvent,
        intelligence: BusinessIntelligenceResult,
        policy_version: str = POLICY_VERSION,
    ) -> PolicyEvaluation:
        """Return the same evaluation for identical validated inputs and version."""

        if policy_version != POLICY_VERSION:
            return self._deny(EvidenceCode.INVALID_POLICY_VERSION, EvidenceSource.POLICY)
        if not event.event_id or event.event_id != intelligence.event_id:
            return self._deny(EvidenceCode.IDENTITY_MISMATCH, EvidenceSource.CANONICAL_EVENT)
        if self.classifier.classify(event.event_type) is not intelligence.category:
            return self._deny(EvidenceCode.CATEGORY_MISMATCH, EvidenceSource.CANONICAL_EVENT)
        if not intelligence.reasons:
            return self._deny(EvidenceCode.MISSING_AI_EVIDENCE, EvidenceSource.AI_ANALYSIS)

        action = _action_for(intelligence.recommended_next_step)
        elevated_priority = intelligence.priority in {Priority.HIGH, Priority.CRITICAL}
        if action is RecommendedAction.NONE and (
            elevated_priority or intelligence.urgency is Urgency.HIGH
        ):
            risk = (
                RiskLevel.CRITICAL if intelligence.priority is Priority.CRITICAL else RiskLevel.HIGH
            )
            return PolicyEvaluation(
                decision=DecisionOutcome.DENY,
                action=RecommendedAction.NONE,
                risk=risk,
                evidence=(
                    PolicyEvidence(
                        code=EvidenceCode.CONFLICTING_NO_ACTION_SIGNALS,
                        source=EvidenceSource.POLICY,
                    ),
                ),
            )

        evidence: list[PolicyEvidence] = []
        if intelligence.confidence < self.confidence_threshold:
            evidence.append(
                PolicyEvidence(
                    code=EvidenceCode.LOW_CONFIDENCE,
                    source=EvidenceSource.AI_ANALYSIS,
                    value=intelligence.confidence,
                )
            )
        if elevated_priority:
            evidence.append(
                PolicyEvidence(
                    code=EvidenceCode.ELEVATED_PRIORITY,
                    source=EvidenceSource.AI_ANALYSIS,
                    value=intelligence.priority.value,
                )
            )
        if intelligence.urgency is Urgency.HIGH:
            evidence.append(
                PolicyEvidence(
                    code=EvidenceCode.HIGH_URGENCY,
                    source=EvidenceSource.AI_ANALYSIS,
                    value=intelligence.urgency.value,
                )
            )
        if intelligence.intent is Intent.UNKNOWN:
            evidence.append(
                PolicyEvidence(
                    code=EvidenceCode.UNKNOWN_INTENT,
                    source=EvidenceSource.AI_ANALYSIS,
                    value=intelligence.intent.value,
                )
            )
        if action in _REVIEW_ACTIONS:
            code = (
                EvidenceCode.ESCALATION_RECOMMENDED
                if action is RecommendedAction.ESCALATE
                else EvidenceCode.RECOMMENDATION_REQUIRES_REVIEW
            )
            evidence.append(PolicyEvidence(code=code, source=EvidenceSource.AI_ANALYSIS))

        if evidence:
            return PolicyEvaluation(
                decision=DecisionOutcome.REQUIRE_HUMAN_APPROVAL,
                action=action,
                risk=self._risk_for_review(intelligence),
                evidence=tuple(evidence),
            )
        code = (
            EvidenceCode.NO_ACTION_RECOMMENDED
            if action is RecommendedAction.NONE
            else EvidenceCode.POLICY_CONDITIONS_SATISFIED
        )
        return PolicyEvaluation(
            decision=DecisionOutcome.ALLOW,
            action=action,
            risk=RiskLevel.LOW,
            evidence=(PolicyEvidence(code=code, source=EvidenceSource.POLICY),),
        )

    @staticmethod
    def _deny(code: EvidenceCode, source: EvidenceSource) -> PolicyEvaluation:
        return PolicyEvaluation(
            decision=DecisionOutcome.DENY,
            action=RecommendedAction.NONE,
            risk=RiskLevel.HIGH,
            evidence=(PolicyEvidence(code=code, source=source),),
        )

    @staticmethod
    def _risk_for_review(intelligence: BusinessIntelligenceResult) -> RiskLevel:
        if intelligence.priority is Priority.CRITICAL:
            return RiskLevel.CRITICAL
        if (
            intelligence.priority is Priority.HIGH
            or intelligence.urgency is Urgency.HIGH
            or intelligence.recommended_next_step is RecommendedNextStep.ESCALATE
        ):
            return RiskLevel.HIGH
        return RiskLevel.MEDIUM


@dataclass(frozen=True, slots=True)
class PolicyDecisionService:
    """Attach server time and safe audit logs outside the pure policy calculation."""

    engine: DeterministicPolicyEngine
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def decide(
        self, event: CanonicalBusinessEvent, intelligence: BusinessIntelligenceResult
    ) -> PolicyDecision:
        _LOGGER.info(
            "policy_evaluation_requested",
            extra={
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "policy_version": POLICY_VERSION,
                "outcome": "requested",
            },
        )
        evaluation = self.engine.evaluate(event, intelligence)
        result = PolicyDecision(
            decision=evaluation.decision,
            action=evaluation.action,
            risk=evaluation.risk,
            policy_version=POLICY_VERSION,
            confidence_threshold=self.engine.confidence_threshold,
            evidence=list(evaluation.evidence),
            event_id=event.event_id,
            generated_at=self.clock(),
        )
        _LOGGER.info(
            "policy_evaluation_completed",
            extra={
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "decision": result.decision.value,
                "action": result.action.value,
                "risk": result.risk.value,
                "policy_version": result.policy_version,
                "outcome": "success",
            },
        )
        return result


def _action_for(recommendation: RecommendedNextStep) -> RecommendedAction:
    """Map one closed advisory enum to one closed policy enum."""

    match recommendation:
        case RecommendedNextStep.NO_ACTION:
            return RecommendedAction.NONE
        case RecommendedNextStep.REVIEW:
            return RecommendedAction.REVIEW
        case RecommendedNextStep.CONTACT_HUMAN:
            return RecommendedAction.CONTACT_HUMAN
        case RecommendedNextStep.REQUEST_INFORMATION:
            return RecommendedAction.REQUEST_INFORMATION
        case RecommendedNextStep.ESCALATE:
            return RecommendedAction.ESCALATE
        case RecommendedNextStep.SCHEDULE_CONSULTATION:
            return RecommendedAction.SCHEDULE_CONSULTATION
        case RecommendedNextStep.NURTURE:
            return RecommendedAction.NURTURE
