"""Agent loop: LLM proposes, human approves, PowerShell executes, everything is logged."""
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

import config
import llm
import tools
from executors import graph_client

console = Console()
AUDIT = Path(__file__).parent / "audit" / "audit.log"
PS_DIR = Path(__file__).parent / "executors" / "powershell"


def audit(event: str, detail: dict):
    """Append-only structured audit line. The governance selling point of the whole build."""
    line = json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                       "event": event, **detail})
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _print_table(rows: list[dict], title: str):
    if not rows:
        console.print(f"[green]No results for {title}.[/green]")
        return
    t = Table(title=title, show_lines=False)
    for col in rows[0].keys():
        t.add_column(col)
    for r in rows[:50]:
        t.add_row(*[str(v) for v in r.values()])
    console.print(t)
    if len(rows) > 50:
        console.print(f"[dim]â€¦and {len(rows) - 50} more[/dim]")


def _run_all_checks_display():
    """Run every detection, print a consolidated summary plus HIGH-risk detail, and return
    a compact result for the LLM to narrate."""
    report = graph_client.run_all_checks()
    summary = []
    for check, data in report.items():
        status = "ERROR" if data["error"] else ("review" if data["high"] else "ok")
        summary.append({
            "check": check,
            "findings": data["count"],
            "high_risk": data["high"],
            "status": status,
        })
    _print_table(summary, "Identity risk summary - all checks")
    for check, data in report.items():
        highs = [r for r in data["rows"] if str(r.get("risk", "")).upper() == "HIGH"]
        if highs:
            _print_table(highs, f"HIGH findings - {check}")
    total_high = sum(d["high"] for d in report.values())
    audit("read", {"tool": "run_all_checks", "args": {},
                   "result_count": sum(d["count"] for d in report.values()),
                   "high": total_high})
    compact = {c: {"findings": d["count"], "high": d["high"], "error": d["error"]}
               for c, d in report.items()}
    return {"summary": compact, "total_high": total_high}


def run_read_tool(name: str, args: dict):
    if name == "run_all_checks":
        return _run_all_checks_display()
    days = args.get("days", config.STALE_DAYS_DEFAULT)
    if name == "find_stale_accounts":
        rows = graph_client.find_stale_accounts(days)
        _print_table(rows, f"Member accounts created >= {days} days ago")
    elif name == "find_stale_guests":
        rows = graph_client.find_stale_guests(days)
        _print_table(rows, f"Guest accounts created >= {days} days ago")
    elif name == "find_privileged_roles":
        rows = graph_client.find_privileged_roles()
        _print_table(rows, "Privileged directory role holders")
    elif name == "find_expiring_secrets":
        rows = graph_client.find_expiring_secrets(args.get("days", 30))
        _print_table(rows, "App registration secrets/certs expiring soon")
    elif name == "find_risky_consents":
        rows = graph_client.find_risky_consents()
        _print_table(rows, "OAuth consent grants (app access risk)")
    elif name == "find_app_permissions":
        rows = graph_client.find_app_permissions()
        _print_table(rows, "Application permissions (app-only access)")
    else:
        rows = [{"error": f"unknown read tool {name}"}]
    audit("read", {"tool": name, "args": args, "result_count": len(rows)})
    return rows


def run_write_tool(name: str, args: dict) -> dict:
    """GATED. Show the proposal, require explicit approval, then execute + log."""
    console.print(Panel.fit(
        f"[bold]Tool:[/bold] {name}\n"
        f"[bold]Args:[/bold] {json.dumps(args, indent=2)}\n"
        f"[bold]Dry run:[/bold] {config.DRY_RUN}",
        title="[yellow]PROPOSED CHANGE â€” approval required[/yellow]", border_style="yellow"))

    audit("proposal", {"tool": name, "args": args})
    decision = console.input("[bold red]Approve this change? (y/N): [/bold red]").strip().lower()

    if decision != "y":
        audit("declined", {"tool": name, "args": args})
        console.print("[green]Declined. Nothing was changed.[/green]")
        return {"status": "declined", "tool": name, "args": args}

    if config.DRY_RUN:
        audit("approved_dryrun", {"tool": name, "args": args})
        console.print("[cyan]DRY_RUN=true â†’ approved but not executed.[/cyan]")
        return {"status": "approved_dryrun", "tool": name, "args": args}

    result = _execute(name, args)
    audit("executed", {"tool": name, "args": args, "result": result})
    return {"status": "executed", "tool": name, "args": args, "result": result}


def _execute(name: str, args: dict) -> str:
    if name == "disable_account":
        script = PS_DIR / "Disable-Account.ps1"
        env = {**os.environ,
               "TENANT_ID": config.TENANT_ID,
               "CLIENT_ID": config.CLIENT_ID,
               "CLIENT_SECRET": config.CLIENT_SECRET}
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-File", str(script),
             "-Upn", args["upn"], "-Reason", args.get("reason", "")],
            capture_output=True, text=True, env=env)
        if proc.returncode != 0:
            return f"ERROR: {proc.stderr.strip()}"
        return proc.stdout.strip()
    return f"no executor for {name}"


def handle_turn(messages: list[dict]) -> list[dict]:
    """One user turn may involve several tool calls; loop until the model stops calling tools."""
    while True:
        resp = llm.complete(messages, tools.api_tools())
        if resp["text"]:
            console.print(f"\n[bold cyan]agent>[/bold cyan] {resp['text']}\n")

        if not resp["tool_calls"]:
            messages.append({"role": "assistant", "content": resp["text"]})
            return messages

        # record the assistant turn (with tool_use blocks) for the Anthropic path
        messages.append({"role": "assistant", "content": resp["raw"].content
                         if config.LLM_PROVIDER == "anthropic" else resp["text"]})

        tool_results = []
        for call in resp["tool_calls"]:
            if call["name"] in tools.WRITE_TOOLS:
                result = run_write_tool(call["name"], call["input"])
            else:
                result = run_read_tool(call["name"], call["input"])
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": call["id"],
                "content": json.dumps(result)[:6000],
            })
        messages.append({"role": "user", "content": tool_results})





