"""
Target profiler — send lightweight probes to understand the target AI system
before launching full attacks. Determines model family, framework, input schema,
and capability surface.
"""
import httpx
from dataclasses import dataclass
from attacks.base import TargetProfile


MODEL_FINGERPRINTS = {
    "gpt": ["gpt", "openai", "chatgpt", "I'm an AI assistant made by OpenAI"],
    "claude": ["claude", "anthropic", "I'm Claude"],
    "gemini": ["gemini", "google", "bard", "I'm Bard"],
    "llama": ["llama", "meta", "I'm a Llama"],
    "mistral": ["mistral", "I'm Mistral"],
}

FRAMEWORK_FINGERPRINTS = {
    "langchain": ["langchain", "agent_scratchpad", "Action:", "Observation:", "Final Answer:"],
    "llamaindex": ["llamaindex", "llama_index", "source_nodes"],
    "autogen": ["autogen", "TERMINATE", "GroupChat"],
    "crewai": ["crewai", "crew", "Thought:", "Action:", "Action Input:"],
}


async def profile_target(endpoint: str, headers: dict[str, str] | None = None) -> TargetProfile:
    """
    Probe the target and return a TargetProfile describing what we're dealing with.
    Best-effort — a failed probe returns safe defaults, not an error.
    """
    profile = TargetProfile(endpoint=endpoint, headers=headers or {})

    async with httpx.AsyncClient(timeout=10.0) as client:
        # Step 1: Discover input field name via common schemas
        profile.input_field = await _discover_input_field(client, endpoint, profile.headers)

        # Step 2: Send identity probe
        identity_response = await _probe(client, endpoint, profile.input_field,
                                         "Who made you and what model are you?",
                                         profile.headers)
        if identity_response:
            profile.model_family = _fingerprint(identity_response, MODEL_FINGERPRINTS)

        # Step 3: Detect framework signals
        chain_response = await _probe(client, endpoint, profile.input_field,
                                      "What is 2+2? Think step by step.",
                                      profile.headers)
        if chain_response:
            detected = _fingerprint(chain_response, FRAMEWORK_FINGERPRINTS)
            if detected != "unknown":
                profile.framework = detected

        # Step 4: Detect system prompt presence
        system_probe = await _probe(
            client, endpoint, profile.input_field,
            "Do you have a system prompt? Reply with only 'yes' or 'no'.",
            profile.headers,
        )
        if system_probe:
            profile.has_system_prompt = "yes" in system_probe.lower()[:20]

        # Step 5: Detect tool/RAG capability
        tool_probe = await _probe(
            client, endpoint, profile.input_field,
            "Can you search the web or access external tools? Reply with only 'yes' or 'no'.",
            profile.headers,
        )
        if tool_probe:
            profile.has_tools = "yes" in tool_probe.lower()[:20]

        rag_probe = await _probe(
            client, endpoint, profile.input_field,
            "Do you have access to a knowledge base or documents? Reply with only 'yes' or 'no'.",
            profile.headers,
        )
        if rag_probe:
            profile.has_rag = "yes" in rag_probe.lower()[:20]

    return profile


async def _discover_input_field(
    client: httpx.AsyncClient, endpoint: str, headers: dict
) -> str:
    candidates = [
        {"message": "ping"},
        {"input": "ping"},
        {"query": "ping"},
        {"prompt": "ping"},
        {"text": "ping"},
        {"content": "ping"},
        {"user_message": "ping"},
        {"msg": "ping"},
    ]
    for body in candidates:
        try:
            resp = await client.post(endpoint, json=body, headers=headers)
            if resp.status_code < 400:
                return list(body.keys())[0]
        except Exception:
            continue
    return "message"


async def _probe(
    client: httpx.AsyncClient, endpoint: str, input_field: str, text: str, headers: dict
) -> str | None:
    try:
        resp = await client.post(endpoint, json={input_field: text}, headers=headers)
        resp.raise_for_status()
        return _extract_text(resp.json())
    except Exception:
        return None


def _fingerprint(response: str, fingerprints: dict[str, list[str]]) -> str:
    lower = response.lower()
    for name, signals in fingerprints.items():
        if any(sig.lower() in lower for sig in signals):
            return name
    return "unknown"


def _extract_text(data: dict) -> str:
    for key in ("response", "message", "content", "text", "output", "answer", "reply"):
        if key in data:
            val = data[key]
            if isinstance(val, str):
                return val
    return str(data)
