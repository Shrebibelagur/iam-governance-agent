"""Terminal chat entry point for the IAM governance agent."""
from rich.console import Console
import config
from agent import handle_turn

console = Console()

BANNER = f"""[bold]IAM Governance Agent[/bold]
provider={config.LLM_PROVIDER}  model={config.LLM_MODEL}  dry_run={config.DRY_RUN}
Type a request, or 'quit' to exit. Writes always require your approval.
Examples:
  find accounts idle for 120 days
  which guests have never signed in?
  disable the stalest account and tell me why
"""


def main():
    console.print(BANNER)
    messages = []
    while True:
        try:
            user = console.input("[bold green]you>[/bold green] ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if user.lower() in {"quit", "exit"}:
            break
        if not user:
            continue
        messages.append({"role": "user", "content": user})
        messages = handle_turn(messages)
    console.print("\n[dim]Session ended. See audit/audit.log for the full trail.[/dim]")


if __name__ == "__main__":
    main()
