"""Microsoft Graph read layer (FREE-TIER version).

NOTE: signInActivity requires Entra ID P1/P2. This tenant is on the free tier, so detection
here is based on ACCOUNT CREATION AGE (createdDateTime), not last sign-in. That is a weaker
signal than idle-detection ("old" != "unused"), but needs no premium licence. To upgrade to
true idle-detection later, enable an Entra ID P2 trial and restore the signInActivity version.

Client-credentials (app-only) auth via MSAL. Read-only by design."""
from datetime import datetime, timezone
import msal
import requests
import config

_GRAPH = "https://graph.microsoft.com/v1.0"
_SCOPE = ["https://graph.microsoft.com/.default"]


def _token() -> str:
    app = msal.ConfidentialClientApplication(
        client_id=config.CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{config.TENANT_ID}",
        client_credential=config.CLIENT_SECRET,
    )
    result = app.acquire_token_for_client(scopes=_SCOPE)
    if "access_token" not in result:
        raise RuntimeError(f"Token error: {result.get('error_description', result)}")
    return result["access_token"]


def _get_all(path: str, params: dict) -> list[dict]:
    headers = {"Authorization": f"Bearer {_token()}"}
    items, url = [], f"{_GRAPH}{path}"
    first = True
    while url:
        r = requests.get(url, headers=headers, params=params if first else None)
        r.raise_for_status()
        data = r.json()
        items.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        first = False
    return items


def _age_days(iso: str | None) -> int | None:
    if not iso:
        return None
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - dt).days


def find_stale_accounts(days: int) -> list[dict]:
    """FREE-TIER: enabled member users whose account was CREATED more than `days` days ago.
    This flags long-lived accounts for review; it is NOT last-sign-in idle detection."""
    users = _get_all("/users", {
        "$select": "userPrincipalName,displayName,accountEnabled,userType,createdDateTime",
        "$top": "999",
    })
    out = []
    for u in users:
        if not u.get("accountEnabled") or u.get("userType") != "Member":
            continue
        age = _age_days(u.get("createdDateTime"))
        if age is not None and age >= days:
            out.append({
                "upn": u["userPrincipalName"],
                "name": u.get("displayName"),
                "created": (u.get("createdDateTime") or "")[:10],
                "age_days": age,
                "basis": "creation-age (no P1/P2)",
            })
    out.sort(key=lambda x: -x["age_days"])
    return out


def find_stale_guests(days: int) -> list[dict]:
    """FREE-TIER: guest/external users CREATED more than `days` days ago — a common
    access-review target. Creation-age based, not last-sign-in."""
    users = _get_all("/users", {
        "$filter": "userType eq 'Guest'",
        "$select": "userPrincipalName,displayName,accountEnabled,createdDateTime,mail",
        "$top": "999",
    })
    out = []
    for u in users:
        age = _age_days(u.get("createdDateTime"))
        if age is not None and age >= days:
            out.append({
                "upn": u["userPrincipalName"],
                "name": u.get("displayName"),
                "mail": u.get("mail"),
                "enabled": u.get("accountEnabled"),
                "created": (u.get("createdDateTime") or "")[:10],
                "age_days": age,
                "basis": "creation-age (no P1/P2)",
            })
    out.sort(key=lambda x: -x["age_days"])
    return out


def find_privileged_roles() -> list[dict]:
    """List activated Entra directory roles and who holds them. Answers 'who has admin rights'.
    Free-tier compatible. Requires Directory.Read.All (or RoleManagement.Read.Directory)."""
    roles = _get_all("/directoryRoles", {
        "$expand": "members($select=id,displayName,userPrincipalName,accountEnabled)",
    })
    priority = {
        "Global Administrator": 0,
        "Privileged Role Administrator": 1,
        "Privileged Authentication Administrator": 2,
        "Security Administrator": 3,
        "Application Administrator": 4,
        "User Administrator": 5,
    }
    out = []
    for role in roles:
        for m in role.get("members", []) or []:
            out.append({
                "role": role.get("displayName"),
                "member": m.get("displayName") or m.get("userPrincipalName") or m.get("id"),
                "upn": m.get("userPrincipalName", "(non-user)"),
                "type": (m.get("@odata.type", "") or "").split(".")[-1] or "unknown",
                "enabled": m.get("accountEnabled"),
            })
    out.sort(key=lambda x: priority.get(x["role"], 99))
    return out


def find_expiring_secrets(days: int = 30) -> list[dict]:
    """List app registrations whose client secrets or certificates are expired or expire within
    `days` days. Credential-hygiene check. Free-tier compatible. Requires Application.Read.All."""
    apps = _get_all("/applications", {
        "$select": "displayName,appId,passwordCredentials,keyCredentials",
        "$top": "999",
    })
    now = datetime.now(timezone.utc)
    out = []
    for app in apps:
        creds = [("secret", c) for c in (app.get("passwordCredentials") or [])]
        creds += [("certificate", c) for c in (app.get("keyCredentials") or [])]
        for kind, c in creds:
            end = c.get("endDateTime")
            if not end:
                continue
            exp = datetime.fromisoformat(end.replace("Z", "+00:00"))
            days_left = (exp - now).days
            if days_left <= days:
                out.append({
                    "app": app.get("displayName"),
                    "type": kind,
                    "name": c.get("displayName") or "(unnamed)",
                    "expires": end[:10],
                    "days_left": days_left,
                    "status": "EXPIRED" if days_left < 0 else "expiring",
                })
    out.sort(key=lambda x: x["days_left"])
    return out


_HIGH_RISK_SCOPES = {
    "Mail.Read", "Mail.ReadWrite", "Mail.Send",
    "Files.Read.All", "Files.ReadWrite.All",
    "Directory.Read.All", "Directory.ReadWrite.All",
    "User.Read.All", "User.ReadWrite.All",
    "Group.ReadWrite.All", "Sites.ReadWrite.All",
    "Application.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    "offline_access",
}


def _sp_name_map() -> dict:
    """Map service principal object id -> display name, to label consent grants readably."""
    sps = _get_all("/servicePrincipals", {"$select": "id,appId,displayName", "$top": "999"})
    return {sp["id"]: sp.get("displayName", sp["id"]) for sp in sps}


def find_risky_consents() -> list[dict]:
    """Audit OAuth delegated permission grants (the illicit-consent attack surface).
    Flags apps holding high-risk scopes and whether consent is tenant-wide (admin) or per-user.
    Free-tier compatible. Requires Directory.Read.All (already granted)."""
    names = _sp_name_map()
    grants = _get_all("/oauth2PermissionGrants", {})
    out = []
    for g in grants:
        scopes = (g.get("scope") or "").split()
        risky = [s for s in scopes if s in _HIGH_RISK_SCOPES]
        tenant_wide = g.get("consentType") == "AllPrincipals"
        if risky:
            level = "HIGH" if tenant_wide else "medium"
        else:
            level = "info"
        out.append({
            "app": names.get(g.get("clientId"), g.get("clientId")),
            "consent": "tenant-wide (admin)" if tenant_wide else "single user",
            "risky_scopes": ", ".join(risky) if risky else "-",
            "risk": level,
        })
    order = {"HIGH": 0, "medium": 1, "info": 2}
    out.sort(key=lambda x: order.get(x["risk"], 3))
    return out


def find_app_permissions() -> list[dict]:
    """Audit APPLICATION permissions (app-role assignments) held by service principals -
    app-only, tenant-wide access with no user involved (the most powerful app grants).
    Resolves app-role IDs to readable names. Free-tier compatible. Requires Directory.Read.All."""
    high_risk = {
        "Mail.Read", "Mail.ReadWrite", "Mail.Send",
        "Files.Read.All", "Files.ReadWrite.All",
        "Directory.Read.All", "Directory.ReadWrite.All",
        "User.Read.All", "User.ReadWrite.All",
        "Group.Read.All", "Group.ReadWrite.All",
        "Application.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
        "Sites.ReadWrite.All", "AppRoleAssignment.ReadWrite.All",
    }
    sps = _get_all("/servicePrincipals", {
        "$select": "id,displayName,appRoles",
        "$expand": "appRoleAssignments",
        "$top": "999",
    })
    role_names: dict[str, str] = {}
    for sp in sps:
        for r in sp.get("appRoles", []) or []:
            role_names[r.get("id")] = r.get("value") or r.get("displayName") or r.get("id")

    out = []
    for sp in sps:
        for a in sp.get("appRoleAssignments", []) or []:
            perm = role_names.get(a.get("appRoleId"), a.get("appRoleId") or "(unknown)")
            out.append({
                "app": sp.get("displayName") or sp.get("id"),
                "permission": perm,
                "resource": a.get("resourceDisplayName", "-"),
                "risk": "HIGH" if perm in high_risk else "info",
            })
    out.sort(key=lambda x: 0 if x["risk"] == "HIGH" else 1)
    return out


def run_all_checks() -> dict:
    """Run every detection and return a consolidated risk summary.
    Each detection is isolated so one failure doesn't sink the whole report."""
    checks = {
        "stale_accounts": lambda: find_stale_accounts(90),
        "stale_guests": lambda: find_stale_guests(90),
        "privileged_roles": find_privileged_roles,
        "expiring_secrets": lambda: find_expiring_secrets(60),
        "risky_consents": find_risky_consents,
        "app_permissions": find_app_permissions,
        "ca_gaps": find_ca_gaps,
        "ownerless_objects": find_ownerless_objects,
    }
    report = {}
    for name, fn in checks.items():
        try:
            rows = fn()
            high = sum(1 for r in rows if str(r.get("risk", "")).upper() == "HIGH")
            report[name] = {"count": len(rows), "high": high, "rows": rows, "error": None}
        except Exception as e:
            report[name] = {"count": 0, "high": 0, "rows": [], "error": str(e)}
    return report


def find_ca_gaps() -> list[dict]:
    """Audit Conditional Access policies for common gaps: policies not enforcing (report-only
    or disabled), user/group exclusions (bypass holes), whether MFA is required anywhere, and
    whether legacy auth is blocked. Reports 'no policies' as a finding. Requires Policy.Read.All."""
    policies = _get_all("/identity/conditionalAccess/policies", {})
    out = []

    if not policies:
        out.append({
            "policy": "(none)",
            "state": "-",
            "finding": "No Conditional Access policies configured in the tenant",
            "risk": "HIGH",
        })
        return out

    any_mfa = False
    any_block_legacy = False

    for p in policies:
        name = p.get("displayName", "(unnamed)")
        state = p.get("state", "unknown")
        grant = p.get("grantControls") or {}
        controls = [c.lower() for c in (grant.get("builtInControls") or [])]
        conditions = p.get("conditions") or {}
        excl_users = (conditions.get("users") or {}).get("excludeUsers") or []
        excl_groups = (conditions.get("users") or {}).get("excludeGroups") or []
        client_apps = conditions.get("clientAppTypes") or []

        if "mfa" in controls:
            any_mfa = True
        if "block" in controls and any(c in client_apps for c in ("exchangeactivesync", "other")):
            any_block_legacy = True

        if state == "disabled":
            out.append({"policy": name, "state": state,
                        "finding": "Policy is disabled (not protecting)", "risk": "medium"})
        elif state == "enabledForReportingButNotEnforced":
            out.append({"policy": name, "state": "report-only",
                        "finding": "Report-only: logging but NOT enforcing", "risk": "HIGH"})

        if excl_users or excl_groups:
            n = len(excl_users) + len(excl_groups)
            out.append({"policy": name, "state": state,
                        "finding": f"Has {n} user/group exclusion(s) - possible bypass",
                        "risk": "medium"})

    if not any_mfa:
        out.append({"policy": "(tenant)", "state": "-",
                    "finding": "No enabled policy requires MFA", "risk": "HIGH"})
    if not any_block_legacy:
        out.append({"policy": "(tenant)", "state": "-",
                    "finding": "Legacy authentication is not explicitly blocked", "risk": "medium"})

    if not out:
        out.append({"policy": "(all)", "state": "-",
                    "finding": "No obvious gaps detected", "risk": "info"})

    order = {"HIGH": 0, "medium": 1, "info": 2}
    out.sort(key=lambda x: order.get(x["risk"], 3))
    return out



def find_ownerless_objects() -> list[dict]:
    """Find groups and app registrations with no owner assigned - an accountability gap
    (nobody is responsible for the object). Owners are expanded in the main query to avoid
    one call per object. Free-tier compatible. Requires Directory.Read.All (already granted)."""
    out = []

    groups = _get_all("/groups", {
        "$select": "id,displayName,securityEnabled",
        "$expand": "owners($select=id)",
        "$top": "999",
    })
    for g in groups:
        if not (g.get("owners") or []):
            out.append({
                "type": "group",
                "name": g.get("displayName", "(unnamed)"),
                "detail": "security" if g.get("securityEnabled") else "other",
                "finding": "No owner assigned",
                "risk": "medium",
            })

    apps = _get_all("/applications", {
        "$select": "id,displayName,appId",
        "$expand": "owners($select=id)",
        "$top": "999",
    })
    for a in apps:
        if not (a.get("owners") or []):
            out.append({
                "type": "app registration",
                "name": a.get("displayName", "(unnamed)"),
                "detail": a.get("appId", ""),
                "finding": "No owner assigned",
                "risk": "HIGH",
            })

    if not out:
        out.append({"type": "-", "name": "(all)", "detail": "",
                    "finding": "All groups and apps have owners", "risk": "info"})

    order = {"HIGH": 0, "medium": 1, "info": 2}
    out.sort(key=lambda x: order.get(x["risk"], 3))
    return out

