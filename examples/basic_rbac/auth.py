"""Safe role-based authorizer used by the basic PermissionDiff example."""

from permissiondiff import Action, Context, Decision, Resource, Subject


def authorize(
    subject: Subject,
    action: Action,
    resource: Resource,
    context: Context,
) -> Decision:
    """Allow reads within a tenant and reserve deletion for administrators."""
    if subject.tenant != resource.tenant:
        return Decision.DENY
    if action.name == "delete_account":
        return Decision.ALLOW if subject.role == "admin" else Decision.DENY
    if action.name == "read_invoice" and subject.role in {"support", "admin"}:
        return Decision.ALLOW
    return Decision.DENY
