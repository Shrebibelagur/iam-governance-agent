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
