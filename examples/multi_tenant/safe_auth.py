"""Correct baseline authorizer for the exact-case diff demonstration."""

from permissiondiff import Action, Context, Decision, Resource, Subject


def authorize(
    subject: Subject,
    action: Action,
    resource: Resource,
    context: Context,
) -> Decision:
    """Require same-tenant support access and deny all other paths."""
    if subject.tenant != resource.tenant:
        return Decision.DENY
    if subject.role == "support" and action.name == "read_invoice":
        return Decision.ALLOW
    return Decision.DENY
