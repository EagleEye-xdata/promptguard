import httpx
from ..models import Target
from ..config import settings
from .secrets import reveal


def extract_text_from_any_response(data: any, custom_field: str | None = None) -> str:
    """
    Universally extracts text from any model response structure.
    """
    if isinstance(data, str):
        return data

    if not isinstance(data, dict):
        return str(data)

    if custom_field and custom_field in data:
        return str(data[custom_field])

    # 1. Standard OpenAI / Groq / DeepSeek / Mistral / xAI Grok / OpenRouter / Together / Perplexity / vLLM / Ollama
    if "choices" in data and isinstance(data["choices"], list) and len(data["choices"]) > 0:
        choice = data["choices"][0]
        if isinstance(choice, dict):
            if "message" in choice and isinstance(choice["message"], dict) and "content" in choice["message"]:
                return str(choice["message"]["content"] or "")
            if "text" in choice:
                return str(choice["text"] or "")

    # 2. Anthropic Claude
    if "content" in data and isinstance(data["content"], list) and len(data["content"]) > 0:
        first = data["content"][0]
        if isinstance(first, dict) and "text" in first:
            return str(first["text"] or "")

    # 3. Google Gemini (REST & SDK shapes)
    if "candidates" in data and isinstance(data["candidates"], list) and len(data["candidates"]) > 0:
        cand = data["candidates"][0]
        if isinstance(cand, dict) and "content" in cand:
            parts = cand["content"].get("parts", [])
            if parts and isinstance(parts, list) and len(parts) > 0 and "text" in parts[0]:
                return str(parts[0]["text"] or "")

    # 4. Cohere v2 & v1
    if "message" in data and isinstance(data["message"], dict) and "content" in data["message"]:
        cont = data["message"]["content"]
        if isinstance(cont, list) and len(cont) > 0 and "text" in cont[0]:
            return str(cont[0]["text"])
        if isinstance(cont, str):
            return cont

    if "generations" in data and isinstance(data["generations"], list) and len(data["generations"]) > 0:
        return str(data["generations"][0].get("text", ""))

    # 5. Common generic fields
    for key in ["response", "answer", "output", "text", "message", "result", "generated_text", "bot_response"]:
        if key in data and data[key] is not None:
            if isinstance(data[key], str):
                return data[key]
            if isinstance(data[key], (int, float, bool)):
                return str(data[key])
            if isinstance(data[key], dict) and "content" in data[key]:
                return str(data[key]["content"])

    return str(data)


async def call_target(target: Target, message: str, session_id: str) -> str:
    headers = {"content-type": "application/json"}
    auth_val = ""
    if target.auth_config_encrypted:
        auth_val = reveal(target.auth_config_encrypted, settings.encryption_key) or ""

    preset = (target.request_format.get("preset") or "").lower()
    endpoint = target.api_endpoint.lower()
    model_name = target.model_name or "gpt-4o-mini"

    # 1. Google Gemini Native API Format
    if preset == "gemini" or ("generativelanguage.googleapis.com" in endpoint and "openai" not in endpoint):
        key = auth_val.replace("Bearer ", "").strip()
        if key:
            headers["x-goog-api-key"] = key
        payload = {
            "contents": [{
                "parts": [{"text": message}]
            }],
            "generationConfig": {
                "maxOutputTokens": 1024,
                "temperature": 0.7
            }
        }
    # 2. Anthropic Claude Format
    elif preset == "anthropic" or "anthropic.com" in endpoint:
        if auth_val:
            headers["x-api-key"] = auth_val.replace("Bearer ", "").strip()
        headers["anthropic-version"] = "2023-06-01"
        payload = {
            "model": model_name or "claude-3-5-haiku-20241022",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": message}]
        }
    # 3. Cohere Format
    elif preset == "cohere" or "cohere.com" in endpoint:
        if auth_val:
            headers["authorization"] = auth_val if auth_val.startswith("Bearer ") or " " in auth_val else f"Bearer {auth_val}"
        payload = {
            "model": model_name or "command-r-plus-08-2024",
            "messages": [{"role": "user", "content": message}]
        }
    # 4. Generic REST JSON Webhook
    elif preset == "generic_json":
        if auth_val:
            headers["authorization"] = auth_val if auth_val.startswith("Bearer ") or " " in auth_val else f"Bearer {auth_val}"
        msg_field = target.request_format.get("message_field", "message")
        payload = {msg_field: message, "session_id": session_id}
        if model_name:
            payload["model"] = model_name
    # 5. Standard OpenAI Format (Covers OpenAI, Grok, Groq, DeepSeek, Mistral, OpenRouter, Together, Perplexity, Qwen, Ollama, vLLM)
    else:
        if auth_val:
            headers["authorization"] = auth_val if auth_val.startswith("Bearer ") or " " in auth_val else f"Bearer {auth_val}"
        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": message}]
        }

    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(target.api_endpoint, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()

    custom_text_field = target.response_format.get("text_field") if target.response_format else None
    return extract_text_from_any_response(data, custom_text_field)
