"""Domain-specific exceptions exposed by PermissionDiff."""


class PermissionDiffError(Exception):
    """Base class for expected PermissionDiff failures."""


class ConfigurationError(PermissionDiffError):
    """Raised when configuration is missing or invalid."""


class AdapterError(PermissionDiffError):
    """Raised when an authorizer or custom invariant cannot be loaded."""


class EvaluationError(PermissionDiffError):
    """Raised when authorizer evaluation crashes, hangs, or returns invalid data."""


class SnapshotVersionError(PermissionDiffError):
    """Raised when a snapshot schema is unsupported."""


class InvariantDefinitionError(PermissionDiffError):
    """Raised when an invariant declaration is invalid."""


class InvariantEvaluationError(PermissionDiffError):
    """Raised when a custom invariant crashes, terminates the process, or returns invalid data.

    Distinct from ``InvariantDefinitionError`` (a configuration problem, exit 2): this is a
    runtime evaluation failure and maps to the evaluation/runtime exit code (3). A custom
    invariant that raises ``SystemExit``/``KeyboardInterrupt`` must surface as this error so an
    incomplete evaluation can never be reported as success.
    """
