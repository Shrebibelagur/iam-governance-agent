"""Tool schemas exposed to the model. READ tools run immediately; WRITE tools are gated.
`write: True` is the flag the agent uses to route a call through the approval prompt.

FREE-TIER note: last-sign-in data (signInActivity) needs Entra ID P1/P2, so on the free tier
the stale-account read tools filter by ACCOUNT CREATION AGE (createdDateTime), not idle time."""

TOOLS = [
    {
        "name": "find_stale_accounts",
        "description": "Find enabled member users whose account was CREATED more than a given "
                       "number of days ago (creation-age based, because last-sign-in data needs "
                       "Entra ID P1/P2 which this tenant lacks). Use this to surface long-lived "
                       "accounts for review. Read-only.",
        "input_schema": {
            "type": "object",
            "properties": {
                "days": {"type": "integer",
                         "description": "Minimum account age in days (e.g. 30)."}
            },
            "required": ["days"],
        },
        "write": False,
    },
    {
        "name": "find_stale_guests",
        "description": "Find guest/external users whose account was CREATED more than a given "
                       "number of days ago (creation-age based, same P1/P2 limitation). A common "
                       "access-review target. Read-only.",
        "input_schema": {
            "type": "object",
            "properties": {
                "days": {"type": "integer",
                         "description": "Minimum account age in days (e.g. 30)."}
            },
            "required": ["days"],
        },
        "write": False,
    },
    {
        "name": "find_privileged_roles",
        "description": "List who holds privileged Entra directory roles (Global Administrator, "
                       "Privileged Role Administrator, User Administrator, Security Administrator, "
                       "etc.) with their account details. Use to answer 'who has admin rights' or "
                       "to review privileged access. Read-only.",
        "input_schema": {
            "type": "object",
            "properties": {},
        },
        "write": False,
    },
    {
        "name": "find_expiring_secrets",
        "description": "List app registrations whose client secrets or certificates are expired "
                       "or expire within a given number of days. Credential-hygiene / secret-"
                       "lifecycle check. Read-only.",
        "input_schema": {
            "type": "object",
            "properties": {
                "days": {"type": "integer",
                         "description": "Expiry window in days (default 30)."}
            },
        },
        "write": False,
    },
    {
        "name": "find_risky_consents",
        "description": "Audit OAuth delegated permission grants across the tenant (the illicit-"
                       "consent attack surface). Lists which apps hold which scopes, whether consent "
                       "is tenant-wide (admin) or per-user, and flags high-risk scopes such as "
                       "Mail.Read, Files.ReadWrite.All, Directory access. Use to answer 'what apps "
                       "can access our data' or to review app consent risk. Read-only.",
        "input_schema": {
            "type": "object",
            "properties": {},
        },
        "write": False,
    },
    {
        "name": "find_app_permissions",
        "description": "Audit APPLICATION permissions (app-role assignments) held by service "
                       "principals - app-only, tenant-wide access granted to apps with no user "
                       "involved. These are the most powerful app grants (e.g. Mail.Read or "
                       "Directory.ReadWrite.All as the app itself). Complements find_risky_consents "
                       "(which covers delegated grants). Flags high-risk permissions. Read-only.",
        "input_schema": {
            "type": "object",
            "properties": {},
        },
        "write": False,
    },
    {
        "name": "disable_account",
        "description": "Disable a user account by UPN. This is a WRITE action and requires "
                       "human approval before it executes.",
        "input_schema": {
            "type": "object",
            "properties": {
                "upn": {"type": "string", "description": "userPrincipalName to disable."},
                "reason": {"type": "string",
                           "description": "Short justification for the audit log."}
            },
            "required": ["upn", "reason"],
        },
        "write": True,
    },
]


def api_tools() -> list[dict]:
    return [{k: v for k, v in t.items() if k != "write"} for t in TOOLS]


WRITE_TOOLS = {t["name"] for t in TOOLS if t["write"]}
