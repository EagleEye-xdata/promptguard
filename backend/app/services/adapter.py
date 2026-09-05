import httpx
from ..models import Target
from ..config import settings
from .secrets import reveal


def extract_text_from_any_response(data: any, custom_field: str | None = None) -> str:
    """
    Extracts text from Hugging Face API, Serverless Router, or target response structures.
    """
    if isinstance(data, str):
        return data

    if isinstance(data, list):
        if len(data) == 0:
            return ""
        first = data[0]
        if isinstance(first, str):
            return first
        if isinstance(first, dict):
            if "generated_text" in first:
                return str(first["generated_text"] or "")
            return extract_text_from_any_response(first, custom_field)
        return str(first)

    if not isinstance(data, dict):
        return str(data)

    if custom_field and custom_field in data:
        return str(data[custom_field])

    # 1. Hugging Face Router & OpenAI-compatible Chat format
    if "choices" in data and isinstance(data["choices"], list) and len(data["choices"]) > 0:
        choice = data["choices"][0]
        if isinstance(choice, dict):
            if "message" in choice and isinstance(choice["message"], dict) and "content" in choice["message"]:
                return str(choice["message"]["content"] or "")
            if "text" in choice:
                return str(choice["text"] or "")

    # 2. Hugging Face single dict output
    if "generated_text" in data:
        return str(data["generated_text"] or "")

    # 3. Generic standard response fields
    for key in ["response", "answer", "output", "text", "message", "result"]:
        if key in data and data[key] is not None:
            if isinstance(data[key], str):
                return data[key]
            if isinstance(data[key], (int, float, bool)):
                return str(data[key])
            if isinstance(data[key], dict) and "content" in data[key]:
                return str(data[key]["content"])

    return str(data)


async def call_target(target: Target, message: str, session_id: str) -> str:
    """
    Dispatches prompt to configured Hugging Face target model or custom target bot endpoint.
    """
    auth_val = ""
    if target.auth_config_encrypted:
        auth_val = reveal(target.auth_config_encrypted, settings.encryption_key) or ""

    preset = (target.request_format.get("preset") or "").lower()
    endpoint = (target.api_endpoint or "").lower()
    model_name = target.model_name or "mistralai/Mistral-7B-Instruct-v0.3"

    # Hugging Face Model or Router Target
    if preset == "huggingface" or "huggingface.co" in endpoint:
        from .hf_adapter import call_huggingface_target
        return await call_huggingface_target(
            api_endpoint=target.api_endpoint,
            model_name=model_name,
            token=auth_val,
            prompt=message,
            system_instruction=target.declared_policy,
            custom_text_field=target.response_format.get("text_field") if target.response_format else None
        )

    # Standard / Custom Target Bot API Endpoint
    headers = {"content-type": "application/json"}
    if auth_val:
        headers["authorization"] = auth_val if auth_val.startswith("Bearer ") or " " in auth_val else f"Bearer {auth_val}"

    # Build payload based on format preset
    if preset in ["openai", "openai_chat"] or "api.openai.com" in endpoint or "/v1/chat/completions" in endpoint:
        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": message}]
        }
    else:
        msg_field = target.request_format.get("message_field", "message")
        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": message}],
            msg_field: message,
            "session_id": session_id
        }

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(target.api_endpoint, json=payload, headers=headers)
            if response.status_code != 200:
                try:
                    err_json = response.json()
                    err_detail = err_json.get("error", {}).get("message") or err_json.get("message") or str(err_json)
                except Exception:
                    err_detail = response.text or f"HTTP {response.status_code}"
                
                if response.status_code == 401:
                    return f"[Target API Error 401 Unauthorized]: {err_detail} (Invalid or expired API Key)"
                elif response.status_code == 429:
                    return f"[Target API Error 429 Rate Limit Exceeded]: {err_detail}"
                elif response.status_code == 404:
                    return f"[Target API Error 404 Not Found]: Endpoint {target.api_endpoint} not found."
                else:
                    return f"[Target API Error {response.status_code}]: {err_detail}"

            data = response.json()
            custom_text_field = target.response_format.get("text_field") if target.response_format else None
            return extract_text_from_any_response(data, custom_text_field)
    except httpx.ConnectError:
        return f"[Target Connection Error]: Could not connect to {target.api_endpoint}. Ensure the server is online."
    except httpx.TimeoutException:
        return f"[Target Timeout Error]: Target {target.api_endpoint} timed out after 60 seconds."
    except Exception as exc:
        return f"[Target Request Failed]: {str(exc)}"

