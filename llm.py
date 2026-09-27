"""Swappable LLM backend. The agent only calls `complete()` — provider is config-driven,
so moving from Anthropic to Azure OpenAI never touches agent logic."""
import json
import config

SYSTEM_PROMPT = (
    "You are an IAM governance assistant for a Microsoft Entra ID environment. "
    "You help identify identity risks (stale accounts, unused guests, over-privileged users) "
    "and propose remediations. You NEVER claim to have changed anything yourself — all writes "
    "go through a human approval gate handled by the host application. When you want a change made, "
    "call the appropriate tool; the host will ask the human to approve. Be concise and specific: "
    "cite UPNs, dates, and day-counts. Recommend the least-privilege, lowest-blast-radius action."
)


def complete(messages: list[dict], tools: list[dict]) -> dict:
    """Send messages + tools, return a normalised dict:
    { 'text': str, 'tool_calls': [ {id, name, input} ] }"""
    if config.LLM_PROVIDER == "anthropic":
        return _anthropic(messages, tools)
    if config.LLM_PROVIDER == "azure":
        return _azure(messages, tools)
    raise RuntimeError(f"Unknown LLM_PROVIDER: {config.LLM_PROVIDER}")


def _anthropic(messages, tools):
    from anthropic import Anthropic
    client = Anthropic(api_key=config.ANTHROPIC_API_KEY)
    resp = client.messages.create(
        model=config.LLM_MODEL,
        max_tokens=1500,
        system=SYSTEM_PROMPT,
        tools=tools,
        messages=messages,
    )
    text, tool_calls = "", []
    for block in resp.content:
        if block.type == "text":
            text += block.text
        elif block.type == "tool_use":
            tool_calls.append({"id": block.id, "name": block.name, "input": block.input})
    return {"text": text, "tool_calls": tool_calls, "raw": resp}


def _azure(messages, tools):
    """Minimal Azure OpenAI path. Converts the Anthropic-style tool schema to OpenAI
    function-calling on the fly so the rest of the app is provider-agnostic."""
    import requests
    oai_tools = [{"type": "function",
                  "function": {"name": t["name"], "description": t["description"],
                               "parameters": t["input_schema"]}} for t in tools]
    # Azure needs the system prompt as a message
    oai_messages = [{"role": "system", "content": SYSTEM_PROMPT}] + _to_openai(messages)
    url = (f"{config.AZURE_OPENAI_ENDPOINT}/openai/deployments/"
           f"{config.AZURE_OPENAI_DEPLOYMENT}/chat/completions"
           f"?api-version={config.AZURE_OPENAI_API_VERSION}")
    r = requests.post(url, headers={"api-key": config.AZURE_OPENAI_API_KEY},
                      json={"messages": oai_messages, "tools": oai_tools, "max_tokens": 1500})
    r.raise_for_status()
    msg = r.json()["choices"][0]["message"]
    tool_calls = [{"id": tc["id"], "name": tc["function"]["name"],
                   "input": json.loads(tc["function"]["arguments"])}
                  for tc in msg.get("tool_calls", [])]
    return {"text": msg.get("content") or "", "tool_calls": tool_calls, "raw": msg}


def _to_openai(messages):
    """Best-effort conversion of the Anthropic message list to OpenAI format.
    Kept simple for the lab; extend if you push heavy multi-tool turns through Azure."""
    out = []
    for m in messages:
        if isinstance(m["content"], str):
            out.append({"role": m["role"], "content": m["content"]})
        else:
            out.append({"role": m["role"],
                        "content": " ".join(b.get("text", "") for b in m["content"]
                                            if isinstance(b, dict))})
    return out
