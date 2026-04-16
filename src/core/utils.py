"""
Lab 11 - Helper Utilities
"""
import os
import uuid
import inspect

from openai import AsyncOpenAI


_client = None


def _get_client() -> AsyncOpenAI:
    global _client
    if _client is None:
        api_key = os.environ.get("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise ValueError("OPENAI_API_KEY is not set.")
        _client = AsyncOpenAI(api_key=api_key)
    return _client


async def chat_with_agent(agent, runner, user_message: str, session_id=None):
    """Send a message to the agent and get the response."""
    if session_id and session_id in runner.sessions:
        session = runner.sessions[session_id]
    else:
        from agents.agent import SimpleSession
        session = SimpleSession(id=str(uuid.uuid4()))
        runner.sessions[session.id] = session

    user_text = user_message
    for plugin in runner.plugins:
        checker = getattr(plugin, "check_input", None)
        if checker is None:
            continue
        try:
            result = checker(user_text, session_id=session.id)
        except TypeError:
            result = checker(user_text)
        if result.get("blocked"):
            blocked_text = result.get("message", "Request blocked by input guardrail.")
            session.messages.append({"role": "user", "content": user_message})
            session.messages.append({"role": "assistant", "content": blocked_text})
            return blocked_text, session

    messages = [{"role": "system", "content": agent.instruction}]
    messages.extend(session.messages)
    messages.append({"role": "user", "content": user_text})

    client = _get_client()
    response = await client.chat.completions.create(
        model=agent.model,
        messages=messages,
        temperature=0.2,
    )
    assistant_text = response.choices[0].message.content or ""

    for plugin in runner.plugins:
        checker = getattr(plugin, "check_output", None)
        if checker is None:
            continue
        if inspect.iscoroutinefunction(checker):
            out = await checker(assistant_text)
        else:
            out = checker(assistant_text)
        assistant_text = out.get("response", assistant_text)
        if out.get("blocked"):
            break

    session.messages.append({"role": "user", "content": user_message})
    session.messages.append({"role": "assistant", "content": assistant_text})
    return assistant_text, session
