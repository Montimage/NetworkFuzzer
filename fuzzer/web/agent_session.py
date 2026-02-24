"""Per-session LangGraph agent manager for the web chat interface."""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

MAX_HISTORY = 50
MAX_SESSIONS = 64
SESSION_TTL = 3600  # 1 hour


@dataclass
class _Message:
    role: str
    content: str
    tool: Optional[str] = None
    tool_input: Optional[str] = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool:
            d["tool"] = self.tool
        if self.tool_input:
            d["tool_input"] = self.tool_input
        return d


@dataclass
class AgentSession:
    """Single chat session wrapping a LangGraph agent."""

    session_id: str
    project_root: Optional[str] = None
    _agent: Any = field(default=None, repr=False)
    _history: list[tuple[str, str]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    last_active: float = field(default_factory=time.monotonic)

    def _ensure_agent(self) -> Any:
        """Lazy-init the LangGraph agent on first use."""
        if self._agent is not None:
            return self._agent
        try:
            from langchain_openai import ChatOpenAI
            from fuzzer.agent.agent import create_networkfuzzer_agent

            llm = ChatOpenAI(model="gpt-4")
            self._agent = create_networkfuzzer_agent(llm, project_root=self.project_root)
            return self._agent
        except Exception as e:
            raise RuntimeError(
                f"Failed to initialize agent: {e}. "
                "Ensure OPENAI_API_KEY is set and langchain dependencies are installed."
            ) from e

    def run(self, user_message: str) -> list[dict]:
        """Run the agent with a user message and return response messages.

        Returns a list of dicts: [{role, content, tool?, tool_input?}, ...]
        """
        with self._lock:
            self.last_active = time.monotonic()
            self._history.append(("user", user_message))

            # Trim history
            if len(self._history) > MAX_HISTORY:
                self._history = self._history[-MAX_HISTORY:]

            agent = self._ensure_agent()
            messages = [("user" if r == "user" else "assistant", c) for r, c in self._history]

            result = agent.invoke({"messages": messages})
            raw_messages = result.get("messages", [])

            response_msgs: list[_Message] = []
            for msg in raw_messages:
                # Skip user messages we already have
                if getattr(msg, "type", None) == "human":
                    continue

                # Tool call messages
                if hasattr(msg, "tool_calls") and msg.tool_calls:
                    for tc in msg.tool_calls:
                        response_msgs.append(_Message(
                            role="assistant",
                            content=f"Calling tool: {tc['name']}",
                            tool=tc["name"],
                            tool_input=str(tc.get("args", "")),
                        ))
                # Tool result messages
                elif getattr(msg, "type", None) == "tool":
                    content = msg.content if isinstance(msg.content, str) else str(msg.content)
                    response_msgs.append(_Message(
                        role="tool",
                        content=content[:2000],  # Truncate long tool outputs
                        tool=getattr(msg, "name", None),
                    ))
                # Regular AI messages
                elif hasattr(msg, "content") and msg.content:
                    response_msgs.append(_Message(role="assistant", content=msg.content))

            # Store final assistant response in history
            for m in reversed(response_msgs):
                if m.role == "assistant" and not m.tool:
                    self._history.append(("assistant", m.content))
                    break

            return [m.to_dict() for m in response_msgs]


class AgentSessionManager:
    """Manages per-session agents with LRU eviction."""

    def __init__(self, project_root: Optional[str] = None):
        self._sessions: OrderedDict[str, AgentSession] = OrderedDict()
        self._project_root = project_root
        self._lock = threading.Lock()

    def get_or_create(self, session_id: str) -> AgentSession:
        with self._lock:
            if session_id in self._sessions:
                self._sessions.move_to_end(session_id)
                return self._sessions[session_id]

            # Evict oldest if at capacity
            while len(self._sessions) >= MAX_SESSIONS:
                self._sessions.popitem(last=False)

            session = AgentSession(
                session_id=session_id,
                project_root=self._project_root,
            )
            self._sessions[session_id] = session
            return session

    def delete(self, session_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(session_id, None) is not None
