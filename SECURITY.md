# Security policy

## Supported versions

PermissionDiff is currently an alpha project. Security fixes are made on the latest release
and the `main` branch.

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| Earlier versions | No |

## Reporting a vulnerability

Please report suspected vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/abishekgiri/permissiondiff/security/advisories/new).
Do not open a public issue or include sensitive details in a pull request.

Include the affected version or commit, impact, reproduction steps, and any suggested
mitigation. You should receive an acknowledgement as soon as the report is reviewed. We will
coordinate validation, remediation, credit, and public disclosure with you through the private
advisory.

## Scope reminder

PermissionDiff executes configured Python authorizers with the operating-system permissions of
the current user. Its subprocess timeout limits hangs and crashes; it is not a security sandbox.
Only evaluate trusted code in an isolated development or CI environment, and never connect test
authorizers to production systems or secrets.
