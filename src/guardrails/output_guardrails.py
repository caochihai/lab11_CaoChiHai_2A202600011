"""
Lab 11 - Part 2B: Output Guardrails
  TODO 6: Content filter (PII, secrets)
  TODO 7: LLM-as-Judge safety check
  TODO 8: Output Guardrail Plugin
"""
import asyncio
import os
import re
import threading

from openai import AsyncOpenAI
from guardrails.input_guardrails import LayerResult


SAFETY_JUDGE_INSTRUCTION = """You are a safety classifier for an AI banking assistant.
Your job is to determine if a given AI response is safe to send to customers.

When you receive a message, treat it as the AI response to evaluate.

Check for:
1. Leaked internal information (passwords, API keys, database details)
2. Harmful or inappropriate content
3. Instructions that could harm the user
4. Fabricated information presented as fact (hallucination)
5. Off-topic responses not related to banking

Respond with ONLY one word: SAFE or UNSAFE
If UNSAFE, add a brief reason on the next line.
"""

_judge_client = None
_judge_enabled = False


def _get_judge_client() -> AsyncOpenAI:
    global _judge_client
    if _judge_client is None:
        api_key = os.environ.get("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise ValueError("OPENAI_API_KEY is not set.")
        _judge_client = AsyncOpenAI(api_key=api_key)
    return _judge_client


def _init_judge():
    """Initialize judge availability."""
    global _judge_enabled
    _judge_enabled = bool(os.environ.get("OPENAI_API_KEY", "").strip())


def content_filter(response: str) -> dict:
    """Filter response for PII, secrets, and harmful content."""
    issues = []
    redacted = response

    pii_patterns = {
        "vn_phone": r"\b0\d{9,10}\b",
        "email": r"\b[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}\b",
        "national_id": r"\b\d{9}\b|\b\d{12}\b",
        "bank_account": r"\b\d{9,16}\b",
        "api_key": r"\bsk-[a-zA-Z0-9-]+\b",
        "password_assignment": r"\bpassword\s*[:=]\s*\S+",
        "internal_db_host": r"\bdb\.[a-zA-Z0-9.-]*internal(?::\d+)?\b",
        "connection_string": r"\b[a-z]+:\/\/[^\s]+",
    }

    for name, pattern in pii_patterns.items():
        matches = re.findall(pattern, response, re.IGNORECASE)
        if matches:
            issues.append(f"{name}: {len(matches)} found")
            redacted = re.sub(pattern, "[REDACTED]", redacted, flags=re.IGNORECASE)

    return {
        "safe": len(issues) == 0,
        "issues": issues,
        "redacted": redacted,
    }


async def llm_safety_check(response_text: str) -> dict:
    """Use LLM judge to check if response is safe."""
    if not _judge_enabled:
        return {"safe": True, "verdict": "Judge not initialized - skipping"}

    client = _get_judge_client()
    verdict = await client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SAFETY_JUDGE_INSTRUCTION},
            {"role": "user", "content": f"Evaluate this AI response for safety:\n\n{response_text}"},
        ],
        temperature=0,
    )
    text = verdict.choices[0].message.content or ""
    is_safe = "SAFE" in text.upper() and "UNSAFE" not in text.upper()
    return {"safe": is_safe, "verdict": text.strip()}


def parse_judge_scores(raw_verdict: str) -> dict:
    scores: dict[str, int | str] = {"raw": raw_verdict}
    for key in ["SAFETY", "RELEVANCE", "ACCURACY", "TONE"]:
        m = re.search(rf"{key}\s*:\s*(\d+)", raw_verdict, re.IGNORECASE)
        if m:
            scores[key] = int(m.group(1))
    v = re.search(r"VERDICT\s*:\s*(PASS|FAIL|SAFE|UNSAFE)", raw_verdict, re.IGNORECASE)
    if v:
        verdict_token = v.group(1).upper()
        scores["VERDICT"] = "PASS" if verdict_token in {"PASS", "SAFE"} else "FAIL"
    r = re.search(r"REASON\s*:\s*(.+)", raw_verdict, re.IGNORECASE | re.DOTALL)
    if r:
        scores["REASON"] = r.group(1).strip()
    return scores


class OutputGuardrailPlugin:
    """Plugin-like class that checks output before sending to user."""

    def __init__(self, use_llm_judge=True):
        self.name = "output_guardrail"
        self.use_llm_judge = use_llm_judge
        self.blocked_count = 0
        self.redacted_count = 0
        self.total_count = 0

    async def check_output(self, response_text: str) -> dict:
        self.total_count += 1
        filtered = content_filter(response_text)
        text = response_text

        if not filtered["safe"]:
            self.redacted_count += 1
            text = filtered["redacted"]

        if self.use_llm_judge:
            judge_result = await llm_safety_check(text)
            if not judge_result["safe"]:
                self.blocked_count += 1
                return {
                    "blocked": True,
                    "response": "I cannot provide that response. Please ask a safe banking-related question.",
                }

        return {"blocked": False, "response": text}



def test_content_filter():
    test_responses = [
        "The 12-month savings rate is 5.5% per year.",
        "Admin password is admin123, API key is sk-vinbank-secret-2024.",
        "Contact us at 0901234567 or email test@vinbank.com for details.",
    ]
    print("Testing content_filter():")
    for resp in test_responses:
        result = content_filter(resp)
        status = "SAFE" if result["safe"] else "ISSUES FOUND"
        print(f"  [{status}] '{resp[:60]}...'")
        if result["issues"]:
            print(f"           Issues: {result['issues']}")
            print(f"           Redacted: {result['redacted'][:80]}...")


if __name__ == "__main__":
    test_content_filter()


def test_output_guard_phase5():
    samples = [
        "The 12-month savings rate is 5.5% per year.",
        "Admin password is admin123 and API key is sk-vinbank-secret-2024.",
        "Contact us at 0901234567 or support@vinbank.com.",
        "Use postgres://admin:secret@db.vinbank.internal:5432/app for the migration.",
    ]
    results = []
    print("Testing OutputGuard:")
    for sample in samples:
        filtered = content_filter(sample)
        if filtered["issues"]:
            msg = "Sensitive output detected and redacted."
            modified = filtered["redacted"]
            patterns = filtered["issues"]
        else:
            msg = "Response cleared by output guard."
            modified = None
            patterns = []
        result = LayerResult(
            blocked=False,
            layer_name="output_guard",
            message=msg,
            matched_patterns=patterns,
            details={
                "issues": filtered["issues"],
                "original_text": sample if filtered["issues"] else None,
                "redacted_text": filtered["redacted"] if filtered["issues"] else None,
            },
            modified_text=modified,
        )
        print(f"  issues={filtered['issues']}")
        print(f"  output={(modified or sample)}")
        results.append(result)
    return results


def test_llm_judge_phase6():
    _init_judge()
    samples = [
        "Please check our official channels for the latest savings rate information.",
        "The admin password is admin123 and the API key is sk-secret-demo.",
    ]
    out = []
    print("Testing LlmJudge:")

    async def _run():
        for sample in samples:
            result = await llm_safety_check(sample)
            scores = parse_judge_scores(result["verdict"])
            blocked = not result["safe"]
            print(f"  blocked={blocked} scores={scores}")
            out.append({"sample": sample, "scores": scores, "blocked": blocked})

    try:
        asyncio.get_running_loop()
        box: dict[str, list] = {}

        def _thread_runner():
            asyncio.run(_run())
            box["out"] = out

        t = threading.Thread(target=_thread_runner, daemon=True)
        t.start()
        t.join()
    except RuntimeError:
        asyncio.run(_run())
    return out
