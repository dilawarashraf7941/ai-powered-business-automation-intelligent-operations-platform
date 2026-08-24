"""Stable approval failure categories without storage details."""


class ApprovalError(Exception):
    code = "APPROVAL_CONFLICT"
    safe_message = "Approval operation could not be completed."
    status_code = 409


class ApprovalNotFoundError(ApprovalError):
    code = "APPROVAL_NOT_FOUND"
    safe_message = "Approval was not found."
    status_code = 404


class ApprovalExpiredError(ApprovalError):
    code = "APPROVAL_EXPIRED"
    safe_message = "Approval has expired."


class ApprovalConflictError(ApprovalError):
    code = "APPROVAL_CONFLICT"


class ApprovalInvalidStateError(ApprovalError):
    code = "APPROVAL_INVALID_STATE"
    safe_message = "Approval is not in a valid state for this transition."


class ProvenanceIntegrityError(ApprovalError):
    code = "PROVENANCE_INTEGRITY_FAILURE"
    safe_message = "Approval integrity verification failed."
    status_code = 500


class PolicyValidationError(ApprovalError):
    code = "POLICY_VALIDATION_FAILED"
    safe_message = "Policy decision is not eligible for human approval."


class ApprovalValidationError(ApprovalError):
    code = "APPROVAL_VALIDATION_ERROR"
    safe_message = "Approval input is invalid."
    status_code = 422


class ApprovalPersistenceError(ApprovalError):
    code = "APPROVAL_UNAVAILABLE"
    safe_message = "Approval storage is temporarily unavailable."
    status_code = 503


class SchemaCompatibilityError(ApprovalError):
    code = "SCHEMA_INCOMPATIBLE"
    safe_message = "Database schema is incompatible with this application version."
    status_code = 503
