"""Shared exceptions for cloud attack path detection."""

class DetectionEngineError(Exception):
    """Base exception for all detection engine errors."""
    pass


class PolicyConfigurationError(DetectionEngineError):
    """Raised when policy definitions or maintenance windows are invalid."""
    pass


class EventValidationError(DetectionEngineError):
    """Raised when incoming telemetry violates schemas or contains invalid data."""
    pass
