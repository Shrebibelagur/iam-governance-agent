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
        "name": "run_all_checks",
        "description": "Run EVERY detection at once and return a consolidated identity-risk "
                       "summary: stale accounts, stale guests, privileged roles, expiring secrets, "
                       "OAuth consent risk, and application permissions. Use when the user wants a "
                       "full posture review, a risk assessment, or 'run all checks'. Read-only.",
        "input_schema": {
            "type": "object",
            "properties": {},
        },
        "write": False,
    },
    {
        "name": "find_ca_gaps",
        "description": "Audit Conditional Access policies for gaps: policies not enforcing "
                       "(report-only or disabled), user/group exclusions that create bypass holes, "
                       "whether any policy requires MFA, and whether legacy authentication is "
                       "blocked. Reports 'no policies configured' as a finding. Use to review "
                       "access-control policy posture. Read-only.",
        "input_schema": {"type": "object", "properties": {}},
        "write": False,
    },
    {
        "name": "find_ownerless_objects",
        "description": "Find groups and app registrations with no owner assigned - an "
                       "accountability gap where nobody is responsible for the object. "
                       "Ownerless app registrations are higher risk (unmanaged credentials). "
                       "Use to review object ownership / orphaned objects. Read-only.",
        "input_schema": {"type": "object", "properties": {}},
        "write": False,
    },
    {
        "name": "find_nhi_register",
        "description": "Build a non-human identity (NHI) register: every service principal "
                       "scored by privilege, ownership, and credential hygiene, ranked worst "
                       "first. Use to review non-human identities, service principals, or "
                       "'which apps are riskiest'. Read-only.",
        "input_schema": {"type": "object", "properties": {}},
        "write": False,
    },
    {
        "name": "find_compliance_gaps",
        "description": "Run every detection and map each finding to the compliance controls it "
                       "supports (ISO 27001, NIST 800-53, DORA). HIGH findings mark a control as a "
                       "GAP. Use for a compliance-gap report or when asked about ISO/NIST/DORA "
                       "posture. Read-only.",
        "input_schema": {"type": "object", "properties": {}},
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




