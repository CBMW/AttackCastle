class AttackCastleError(Exception):
    """Base exception for application-specific failures."""


class ValidationError(AttackCastleError):
    """Raised for invalid user input or configuration."""


class AdapterError(AttackCastleError):
    """Raised when an adapter encounters an unrecoverable error."""


class PlannerError(AttackCastleError):
    """Raised for workflow planning problems."""

