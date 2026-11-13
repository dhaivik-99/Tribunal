"""One ask() function for any LLM provider. Switch providers in .env, not in code.

.env examples:
  PROVIDER=gemini      GEMINI_API_KEY=...      (free tier)
  PROVIDER=anthropic   ANTHROPIC_API_KEY=...   (paid)
Optional: MODEL=... to override the default model.
"""
import os
import time

from dotenv import load_dotenv

load_dotenv()
PROVIDER = os.environ.get("PROVIDER", "gemini").lower()
MODEL = os.environ.get("MODEL", "")


def _gemini(system, user):
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    response = client.models.generate_content(
        model=MODEL or "gemini-3.8-flash",
        contents=user,
        config=types.GenerateContentConfig(system_instruction=system),
    )
    return response.text or ""


def _anthropic(system, user):
    from anthropic import Anthropic

    client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    response = client.messages.create(
        model=MODEL or "claude-sonnet-5-5",
        max_tokens=1500,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return response.content[0].text


def ask(system, user):
    """Send one prompt. Waits and retries if a free-tier rate limit is hit."""
    call = {"gemini": _gemini, "anthropic": _anthropic}.get(PROVIDER)
    if call is None:
        raise SystemExit("Unknown PROVIDER in .env: " + PROVIDER)
    for attempt in range(6):
        try:
            return call(system, user).strip()
        except Exception as error:
            message = str(error)
            if "429" in message or "RESOURCE_EXHAUSTED" in message or "rate" in message.lower():
                print("    rate limited, waiting 30s ...", flush=True)
                time.sleep(30)
            else:
                raise
    raise SystemExit("Still rate limited after several retries. Try again later.")
