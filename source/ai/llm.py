"""
Minimal LLM client (stdlib only).

Providers:
  offline -> no network; callers use their built-in rule-based fallbacks
  gemini  -> Google Gemini generateContent REST API
  openai  -> any OpenAI-compatible /chat/completions API
             (OpenAI, Groq, OpenRouter, Together, local Ollama / LM Studio)
"""
import json
import re
import urllib.error
import urllib.request

from config import (
    LLM_PROVIDER, LLM_TIMEOUT_SECONDS,
    GEMINI_API_KEY, GEMINI_MODEL,
    OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL,
)


class LLMError(Exception):
    pass


def is_enabled():
    if LLM_PROVIDER == "gemini":
        return bool(GEMINI_API_KEY)
    if LLM_PROVIDER == "openai":
        return bool(OPENAI_API_KEY) or "localhost" in OPENAI_BASE_URL or "127.0.0.1" in OPENAI_BASE_URL
    return False


def engine_name():
    if not is_enabled():
        return "Pilot offline engine"
    if LLM_PROVIDER == "gemini":
        return f"Gemini ({GEMINI_MODEL})"
    return f"{OPENAI_MODEL}"


def _post(url, payload, headers):
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(request, timeout=LLM_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="ignore")[:300]
        raise LLMError(f"HTTP {error.code}: {body}") from error
    except Exception as error:  # timeouts, DNS, bad JSON...
        raise LLMError(str(error)) from error


def complete(system, user, json_mode=False, temperature=0.2):
    if not is_enabled():
        raise LLMError("LLM provider is offline")

    if LLM_PROVIDER == "gemini":
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
        # Newer Gemini models (3.6+) reject sampling params like temperature, so none are sent.
        config = {}
        if json_mode:
            config["responseMimeType"] = "application/json"
        result = _post(url, {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            **({"generationConfig": config} if config else {}),
        }, {"x-goog-api-key": GEMINI_API_KEY})
        try:
            parts = result["candidates"][0]["content"]["parts"]
            return "".join(part.get("text", "") for part in parts).strip()
        except (KeyError, IndexError) as error:
            raise LLMError(f"Unexpected Gemini response: {str(result)[:200]}") from error

    payload = {
        "model": OPENAI_MODEL,
        "temperature": temperature,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}"} if OPENAI_API_KEY else {}
    result = _post(OPENAI_BASE_URL.rstrip("/") + "/chat/completions", payload, headers)
    try:
        return result["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError) as error:
        raise LLMError(f"Unexpected response: {str(result)[:200]}") from error


def complete_json(system, user):
    text = complete(system, user, json_mode=True)
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    try:
        return json.loads(text)
    except ValueError:
        match = re.search(r"\{.*\}", text, re.S)
        if match:
            return json.loads(match.group(0))
        raise LLMError("Model did not return valid JSON")
