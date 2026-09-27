# Security Notes

This project handles credentials for a Microsoft Entra tenant. The following practices apply.

## Secrets
- All secrets (Anthropic API key, tenant/client IDs, client secret) live only in a local
  `.env` file, which is excluded from version control via `.gitignore`.
- No secret values are stored in source code. Configuration is loaded from environment
  variables at runtime.
- The client secret should be rotated periodically and on any suspected exposure.

## Least privilege
- Detection uses read-only Microsoft Graph application permissions.
- The account-disable (write) path is separated from detection and, in production, would use
  a distinct, tightly-scoped app registration.
- `Application.Read.All` reads credential *metadata* only (expiry dates), never secret values,
  which Graph does not expose after creation.

## Auditability
- Every read, proposal, approval, decline and execution is written to an append-only audit log.
- The audit log may contain real identifiers and is excluded from version control.

## Safe defaults
- `DRY_RUN=true` by default: approved actions are logged but not executed until explicitly enabled.
- All write actions require interactive human approval.

## Reporting
This is a personal lab project. For any security concern, open an issue.
