# Policy-engine adapters

PermissionDiff evaluates one callable: `authorize(subject, action, resource, context) -> Decision`.
An **adapter** turns an external policy engine into that callable using the toolkit in
`permissiondiff.adapters`:

- `from_boolean(check)` — wrap any `check(...) -> bool` (the shape of most SDK calls).
- `from_decision(check)` — wrap a `check(...) -> bool | Decision`.
- `http_authorizer(endpoint, build_request=..., parse_allowed=...)` — query an HTTP-JSON policy
  endpoint (OPA and similar) using only the standard library.

Point an adapter at your `permissiondiff.yaml` `authorizer:` (for example
`authorizer: examples.adapters.opa_example:authorize`).

> **Safety:** adapters make read-only decision calls. Point them at a **non-production / test**
> policy instance, never at production data or anything with side effects. Live SDK/HTTP calls run
> inside the evaluation worker; the core engine never imports adapters or performs network I/O.

The modules here are runnable **patterns**, not vendored integrations. `opa_example.py` is exercised
against a local server in the test suite; the SDK examples (`openfga_example.py`, `cedar_example.py`,
`spicedb_example.py`, `auth0_fga_example.py`) import their vendor SDK lazily, so you install only the
one you use. Real end-to-end validation requires the corresponding engine running — wire your own
client and mapping following these skeletons.

| Engine | Example | Reduces to |
| --- | --- | --- |
| Open Policy Agent (OPA) | `opa_example.py` | `http_authorizer` (POST to `/v1/data/.../allow`) |
| OpenFGA | `openfga_example.py` | `from_boolean` over `client.check(...)` |
| Auth0 FGA | `auth0_fga_example.py` | `from_boolean` over the FGA `check(...)` |
| Cedar / AWS Verified Permissions | `cedar_example.py` | `from_decision` over `is_authorized(...)` |
| SpiceDB / Authzed | `spicedb_example.py` | `from_boolean` over `CheckPermission(...)` |
