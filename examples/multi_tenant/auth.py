"""Deliberately vulnerable authorizer used as the PermissionDiff regression fixture."""

from permissiondiff import Action, Context, Decision, Resource, Subject


def authorize(
    subject: Subject,
    action: Action,
    resource: Resource,
    context: Context,
) -> Decision:
    """Allow support reads without checking tenant; this bug is intentional."""
    if subject.role == "admin":
        return Decision.ALLOW
    if subject.role == "support" and action.name == "read_invoice":
        return Decision.ALLOW  # DELIBERATE BUG: cross-tenant reads are allowed
    return Decision.DENY
