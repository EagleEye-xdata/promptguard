import logging
import os
import httpx
from typing import Any
from .adapter import extract_text_from_any_response
from .secrets import reveal
from ..config import settings

logger = logging.getLogger("eaglei.hf_adapter")

HF_DEFAULT_MODEL = os.getenv("HF_MODEL_ID", "mistralai/Mistral-7B-Instruct-v0.3")
HF_ROUTER_URL = "https://router.huggingface.co/hf-inference/v1/chat/completions"
HF_INFERENCE_BASE = "https://api-inference.huggingface.co/models"


async def call_huggingface_target(
    api_endpoint: str | None,
    model_name: str | None,
    token: str | None,
    prompt: str,
    system_instruction: str | None = None,
    timeout: float = 45.0,
    custom_text_field: str | None = None
) -> str:
    """
    Sends a test prompt to Hugging Face API and returns the normalized text response.
    """
    model = model_name or HF_DEFAULT_MODEL
    auth_token = token or os.getenv("HF_TOKEN") or ""
    if auth_token.startswith("Bearer "):
        auth_token = auth_token.replace("Bearer ", "").strip()

    headers = {
        "content-type": "application/json"
    }
    if auth_token:
        headers["authorization"] = f"Bearer {auth_token}"

    endpoint = (api_endpoint or "").strip()
    if not endpoint:
        endpoint = HF_ROUTER_URL

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # 1. Hugging Face Router (OpenAI Compatible)
            if "router.huggingface.co" in endpoint or "/v1/chat/completions" in endpoint:
                messages = []
                if system_instruction:
                    messages.append({"role": "system", "content": system_instruction})
                messages.append({"role": "user", "content": prompt})

                payload = {
                    "model": model,
                    "messages": messages,
                    "max_tokens": 512,
                    "temperature": 0.7
                }
                resp = await client.post(endpoint, json=payload, headers=headers)
                if resp.status_code >= 400:
                    logger.error(f"HF error {resp.status_code}: {resp.text}")
                    try:
                        err_data = resp.json()
                        err_msg = err_data.get("error", {}).get("message") or err_data.get("error") or resp.text
                    except Exception:
                        err_msg = resp.text or f"HTTP {resp.status_code}"
                    return f"[Hugging Face Error {resp.status_code}]: {err_msg}"

                data = resp.json()
                return extract_text_from_any_response(data, custom_text_field)

            # 2. Classic Hugging Face Inference API (/models/<model>)
            elif "api-inference.huggingface.co" in endpoint:
                payload = {
                    "inputs": prompt,
                    "parameters": {
                        "max_new_tokens": 512,
                        "return_full_text": False,
                        "temperature": 0.7
                    }
                }
                resp = await client.post(endpoint, json=payload, headers=headers)
                if resp.status_code >= 400:
                    logger.error(f"HF Inference error {resp.status_code}: {resp.text}")
                    return f"[Hugging Face Inference Error {resp.status_code}]: {resp.text}"

                data = resp.json()
                return extract_text_from_any_response(data, custom_text_field)

            # 3. Custom / Local HF Target Bot Fixture
            else:
                payload = {
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "message": prompt
                }
                resp = await client.post(endpoint, json=payload, headers=headers)
                if resp.status_code >= 400:
                    logger.error(f"Target Bot error {resp.status_code}: {resp.text}")
                    return f"[Target Bot Error {resp.status_code}]: {resp.text}"

                data = resp.json()
                return extract_text_from_any_response(data, custom_text_field)

    except httpx.ConnectError as exc:
        logger.error(f"Connection failed to {endpoint}: {exc}")
        return f"[Connection Error]: Could not connect to {endpoint}. Ensure endpoint URL and network are valid."
    except httpx.TimeoutException:
        logger.error(f"Timeout reaching {endpoint}")
        return f"[Timeout Error]: Hugging Face target {endpoint} timed out after {timeout} seconds."
    except Exception as exc:
        logger.error(f"Unexpected HF adapter error: {exc}")
        return f"[Adapter Error]: {str(exc)}"

