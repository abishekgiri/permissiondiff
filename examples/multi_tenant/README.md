# Multi-tenant vulnerability example

`auth.py` deliberately allows a support user from ACME to read GLOBEX invoices. The example is a demo and a regression guard.

```bash
uv run permissiondiff test --config examples/multi_tenant/permissiondiff.yaml
```

For an exact-case diff, snapshot the safe authorizer and replay that corpus against the vulnerable candidate:

```bash
uv run permissiondiff snapshot --config examples/multi_tenant/baseline.yaml \
  --output .permissiondiff/multi-tenant-main.json
uv run permissiondiff diff --config examples/multi_tenant/permissiondiff.yaml \
  --baseline .permissiondiff/multi-tenant-main.json
```
