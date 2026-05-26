"""Mock LLM client for E2E tests.

Activated via the ``E2E_MOCK_LLM`` environment variable:
  - ``E2E_MOCK_LLM=true``   → playback pre-recorded responses
  - ``E2E_MOCK_LLM=record`` → call real Anthropic API and save responses

Response files: ``fixtures/mock_llm_turns/<turn>.json``
Each file: ``{"prompt_hash": str, "response": str}``

*prompt_hash* = sha256 of the first 2000 chars of ``system_prompt + str(messages)``.
Hash match → return recorded response.
Hash mismatch → raise :class:`MockLLMError`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger("sailor.phase2.mock_llm_client")


class MockLLMError(Exception):
    """Raised when a mock response cannot be matched or recorded."""


class MockLLMClient:
    """Test-only LLM client that replays pre-recorded responses.

    Args:
        fixture_dir: Directory that contains (or will contain) a
            ``mock_llm_turns/`` subdirectory with per-turn JSON files.
    """

    def __init__(self, fixture_dir: Path) -> None:
        self.fixture_dir = fixture_dir / "mock_llm_turns"
        self.turn = 0
        self.mode = os.environ.get("E2E_MOCK_LLM", "").lower()

    def chat(
        self,
        messages: list[dict],
        system_prompt: str = "",
        max_tokens: int = 8192,
    ) -> str:
        """Return the recorded response for the current turn.

        Args:
            messages: Ordered conversation turns (role/content dicts).
            system_prompt: System prompt text.
            max_tokens: Maximum tokens for record mode API call.

        Returns:
            Recorded (or freshly generated) assistant response text.

        Raises:
            MockLLMError: In playback mode when the turn file is missing or
                the prompt hash does not match the recorded hash.
        """
        prompt_text = system_prompt + str(messages)
        prompt_hash = hashlib.sha256(
            prompt_text[:2000].encode()
        ).hexdigest()[:16]

        if self.mode == "record":
            return self._record(prompt_hash, messages, system_prompt, max_tokens)
        return self._playback(prompt_hash)

    def _playback(self, prompt_hash: str) -> str:
        path = self.fixture_dir / f"{self.turn:02d}.json"
        if not path.exists():
            raise MockLLMError(
                f"No mock response for turn {self.turn} at {path}. "
                "Run with E2E_MOCK_LLM=record to generate fixtures."
            )
        recorded = json.loads(path.read_text(encoding="utf-8"))
        if recorded["prompt_hash"] != prompt_hash:
            raise MockLLMError(
                f"Turn {self.turn}: prompt hash mismatch.\n"
                f"  recorded: {recorded['prompt_hash']}\n"
                f"  current:  {prompt_hash}\n"
                "Prompts changed — re-record with E2E_MOCK_LLM=record."
            )
        self.turn += 1
        logger.debug("MockLLMClient: replayed turn %d from %s", self.turn - 1, path)
        return recorded["response"]

    def _record(
        self,
        prompt_hash: str,
        messages: list[dict],
        system_prompt: str,
        max_tokens: int,
    ) -> str:
        import anthropic

        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise MockLLMError(
                "ANTHROPIC_API_KEY not set — required for E2E_MOCK_LLM=record"
            )
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=max_tokens,
            system=[{"type": "text", "text": system_prompt}]
            if system_prompt
            else anthropic.NOT_GIVEN,
            messages=messages,
        )
        result = response.content[0].text if response.content else ""

        self.fixture_dir.mkdir(parents=True, exist_ok=True)
        path = self.fixture_dir / f"{self.turn:02d}.json"
        path.write_text(
            json.dumps({"prompt_hash": prompt_hash, "response": result}, indent=2),
            encoding="utf-8",
        )
        logger.info("MockLLMClient: recorded turn %d → %s", self.turn, path)
        self.turn += 1
        return result


def resolve_llm_client(fixture_dir: Path) -> MockLLMClient | None:
    """Return a :class:`MockLLMClient` if ``E2E_MOCK_LLM`` is set, else ``None``.

    When ``None`` is returned, :class:`~sailor.phase2.llm_orchestrator.LLMOrchestrator`
    falls back to the real Anthropic SDK.

    Args:
        fixture_dir: Workspace ``fixtures/`` directory passed to
            :class:`MockLLMClient`.

    Returns:
        :class:`MockLLMClient` instance in mock/record mode, ``None`` otherwise.
    """
    mock_mode = os.environ.get("E2E_MOCK_LLM", "").lower()
    if mock_mode in ("true", "record"):
        return MockLLMClient(fixture_dir)
    return None
