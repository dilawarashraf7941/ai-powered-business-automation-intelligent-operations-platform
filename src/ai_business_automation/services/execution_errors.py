"""Stable controlled-execution failures without implementation details."""


class ExecutionBoundaryError(Exception):
    code = "EXECUTION_CONFLICT"
    safe_message = "Execution operation could not be completed."
    status_code = 409


class ApprovalNotApprovedError(ExecutionBoundaryError):
    code = "APPROVAL_NOT_APPROVED"
    safe_message = "Approval is not approved for execution."


class ExecutionApprovalExpiredError(ExecutionBoundaryError):
    code = "APPROVAL_EXPIRED"
    safe_message = "Approval has expired."


class ApprovalProvenanceInvalidError(ExecutionBoundaryError):
    code = "APPROVAL_PROVENANCE_INVALID"
    safe_message = "Approval provenance verification failed."
    status_code = 500


class ExecutionAlreadyClaimedError(ExecutionBoundaryError):
    code = "EXECUTION_ALREADY_CLAIMED"
    safe_message = "Execution has already been claimed."


class ExecutionAlreadyCompletedError(ExecutionBoundaryError):
    code = "EXECUTION_ALREADY_COMPLETED"
    safe_message = "Approval has already been executed."


class ExecutionConflictError(ExecutionBoundaryError):
    code = "EXECUTION_CONFLICT"


class ActionNotAllowedError(ExecutionBoundaryError):
    code = "ACTION_NOT_ALLOWED"
    safe_message = "Action is not allowlisted."


class ActionValidationError(ExecutionBoundaryError):
    code = "ACTION_VALIDATION_ERROR"
    safe_message = "Internal action validation failed."
    status_code = 422


class ExecutionFailedError(ExecutionBoundaryError):
    code = "EXECUTION_FAILED"
    safe_message = "Execution definitively failed."
    status_code = 500


class ExecutionUnknownError(ExecutionBoundaryError):
    code = "EXECUTION_UNKNOWN"
    safe_message = "Execution outcome is unknown."
    status_code = 500


class ExecutionIntegrityError(ExecutionBoundaryError):
    code = "EXECUTION_INTEGRITY_FAILURE"
    safe_message = "Execution integrity verification failed."
    status_code = 500


class ExecutionNotFoundError(ExecutionBoundaryError):
    code = "EXECUTION_NOT_FOUND"
    safe_message = "Execution was not found."
    status_code = 404


class ExecutionPersistenceError(ExecutionBoundaryError):
    code = "EXECUTION_UNAVAILABLE"
    safe_message = "Execution storage is temporarily unavailable."
    status_code = 503
