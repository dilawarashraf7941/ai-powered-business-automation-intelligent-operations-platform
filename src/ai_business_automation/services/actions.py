"""Static allowlisted local action registry with bounded deterministic handlers."""

import hashlib
from types import MappingProxyType
from typing import Protocol

from ai_business_automation.models import (
    ActionContext,
    ActionOutcome,
    ExecutionAction,
    HumanReviewInput,
    InternalActionEffect,
    InternalNoteInput,
    InternalPriority,
    InternalStatus,
    InternalStatusInput,
    InternalTaskInput,
    NoOpInput,
    RiskLevel,
)
from ai_business_automation.providers import (
    GHLOutcomeCertainty,
    GHLProvider,
    GHLProviderError,
    UnavailableGHLProvider,
)


class DefinitiveActionFailure(Exception):
    """A local handler definitively did not complete its action."""

    def __init__(self, category: str = "INTERNAL_FAILURE") -> None:
        self.category = category
        super().__init__(category)


class UnknownActionOutcome(Exception):
    """A handler outcome cannot be established and must never be retried automatically."""

    def __init__(self, category: str = "INTERNAL_UNKNOWN") -> None:
        self.category = category
        super().__init__(category)


class ActionHandler(Protocol):
    def execute(self, context: ActionContext) -> ActionOutcome: ...


class NoOpHandler:
    def execute(self, context: ActionContext) -> ActionOutcome:
        NoOpInput()
        return ActionOutcome(
            result_code="COMPLETED",
            safe_summary="Allowlisted no-op completed.",
            effect=InternalActionEffect(object_type="NONE", content="NO_OP"),
        )


class CreateInternalTaskHandler:
    def execute(self, context: ActionContext) -> ActionOutcome:
        task = InternalTaskInput(
            title="Review approved internal event",
            description=f"Complete the approved internal follow-up for event {context.event_id}.",
            priority=_priority(context.risk),
        )
        object_id = _object_id("tsk", context.execution_id)
        return ActionOutcome(
            result_code="COMPLETED",
            safe_summary="Internal task created.",
            effect=InternalActionEffect(
                object_id=object_id,
                object_type="INTERNAL_TASK",
                content=f"{task.title} | {task.description} | {task.priority.value}",
            ),
        )


class UpdateInternalStatusHandler:
    def execute(self, context: ActionContext) -> ActionOutcome:
        update = InternalStatusInput(
            internal_reference=context.event_id,
            status=InternalStatus.REVIEW_REQUIRED,
        )
        return ActionOutcome(
            result_code="COMPLETED",
            safe_summary="Internal status updated.",
            effect=InternalActionEffect(
                object_type="INTERNAL_STATUS",
                content=f"{update.internal_reference}|{update.status.value}",
            ),
        )


class RequestHumanReviewHandler:
    def execute(self, context: ActionContext) -> ActionOutcome:
        review = HumanReviewInput(
            approval_id=context.approval_id,
            event_id=context.event_id,
            reason="Approved policy recommendation requires internal human follow-up.",
        )
        object_id = _object_id("rev", context.execution_id)
        return ActionOutcome(
            result_code="COMPLETED",
            safe_summary="Internal human review requested.",
            effect=InternalActionEffect(
                object_id=object_id,
                object_type="HUMAN_REVIEW",
                content=f"{review.approval_id}|{review.event_id}|{review.reason}",
            ),
        )


class GenerateInternalNoteHandler:
    def execute(self, context: ActionContext) -> ActionOutcome:
        note = InternalNoteInput(text=f"Approved internal follow-up for event {context.event_id}.")
        object_id = _object_id("nte", context.execution_id)
        return ActionOutcome(
            result_code="COMPLETED",
            safe_summary="Internal note generated.",
            effect=InternalActionEffect(
                object_id=object_id,
                object_type="INTERNAL_NOTE",
                content=note.text,
            ),
        )


class GHLAddContactTagHandler:
    """Invoke only the dedicated provider method with approval-bound parameters."""

    def __init__(self, provider: GHLProvider) -> None:
        self._provider = provider

    def execute(self, context: ActionContext) -> ActionOutcome:
        if context.action_parameters is None:
            raise DefinitiveActionFailure("GHL_VALIDATION")
        try:
            self._provider.add_contact_tag(context.action_parameters)
        except GHLProviderError as exc:
            if exc.certainty is GHLOutcomeCertainty.DEFINITIVE:
                raise DefinitiveActionFailure(exc.category.value) from exc
            raise UnknownActionOutcome(exc.category.value) from exc
        return ActionOutcome(
            result_code="COMPLETED",
            safe_summary="GHL contact tag operation completed.",
        )


class ActionRegistry:
    """Closed registry; actions and handlers cannot be registered at runtime."""

    def __init__(self, ghl_provider: GHLProvider | None = None) -> None:
        self._handlers: MappingProxyType[ExecutionAction, ActionHandler] = MappingProxyType(
            {
                ExecutionAction.NO_OP: NoOpHandler(),
                ExecutionAction.CREATE_INTERNAL_TASK: CreateInternalTaskHandler(),
                ExecutionAction.UPDATE_INTERNAL_STATUS: UpdateInternalStatusHandler(),
                ExecutionAction.REQUEST_HUMAN_REVIEW: RequestHumanReviewHandler(),
                ExecutionAction.GENERATE_INTERNAL_NOTE: GenerateInternalNoteHandler(),
                ExecutionAction.GHL_ADD_CONTACT_TAG: GHLAddContactTagHandler(
                    ghl_provider or UnavailableGHLProvider()
                ),
            }
        )

    @property
    def actions(self) -> frozenset[ExecutionAction]:
        return frozenset(self._handlers)

    def execute(self, context: ActionContext) -> ActionOutcome:
        return self._handlers[context.action].execute(context)


def _priority(risk: RiskLevel) -> InternalPriority:
    if risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
        return InternalPriority.HIGH
    if risk is RiskLevel.MEDIUM:
        return InternalPriority.MEDIUM
    return InternalPriority.LOW


def _object_id(prefix: str, execution_id: str) -> str:
    digest = hashlib.sha256(f"{prefix}:{execution_id}".encode()).hexdigest()[:24]
    return f"{prefix}_{digest}"
