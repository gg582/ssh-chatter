#!/usr/bin/env python3
"""Autonomous GPT moderator bot for ssh-chatter.

This script runs outside of the core ssh-chatter server so it can be
maintained independently.  It connects to an ssh-chatter instance over SSH,
joins the room as an operator-capable account, watches chat traffic, issues
warnings, and escalates to kicks or bans when necessary.

Highlights
---------
* Fully autonomous: handles the SSH connection, optional captcha, and chat
  interaction without manual input.
* Moderation policy: sends private warnings for unethical content, removes
  users after five warnings, and bans users for explicitly criminal
  discussions that fall under U.S. law.
* Configurable: command-line options cover host, port, identity, reconnect
  backoff, and keyword overrides.

The script depends on ``asyncssh`` for its SSH transport.  Install it via
``pip install asyncssh`` before running the bot.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import logging
import os
import re
import signal
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import urlparse


# --- Captcha solving ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CaptchaStory:
    """Represents a captcha story used by ssh-chatter."""

    person_name: str
    descriptor: str
    is_male: bool
    pet_species: str
    pet_name: str
    pet_pronoun: Optional[str]
    template_type: str  # either "pronoun" or "species"


CAPTCHA_STORIES: Tuple[CaptchaStory, ...] = (
    CaptchaStory("Jiho", "software engineer", True, "cat", "Hodu", None, "pronoun"),
    CaptchaStory("Sujin", "middle school teacher", False, "cat", "Dubu", None, "pronoun"),
    CaptchaStory("Minseok", "photographer", True, "cat", "Mimi", None, "pronoun"),
    CaptchaStory("Haeun", "florist", False, "cat", "Bori", None, "pronoun"),
    CaptchaStory("Yuna", "product designer", False, "cat", "Choco", None, "pronoun"),
    CaptchaStory("Donghyun", "barista", True, "cat", "Gaeul", None, "pronoun"),
    CaptchaStory("Seojun", "research scientist", True, "cat", "Nuri", None, "pronoun"),
    CaptchaStory("Ara", "ceramic artist", False, "cat", "Bam", None, "pronoun"),
    CaptchaStory("Kyungmin", "chef", True, "cat", "Tori", None, "pronoun"),
    CaptchaStory("Jisoo", "translator", False, "cat", "Haneul", None, "pronoun"),
    CaptchaStory("Emily", "librarian", False, "cat", "Whiskers", None, "pronoun"),
    CaptchaStory("Jacob", "firefighter", True, "cat", "Shadow", None, "pronoun"),
    CaptchaStory("Olivia", "graphic designer", False, "cat", "Pumpkin", None, "pronoun"),
    CaptchaStory("Noah", "high school coach", True, "cat", "Midnight", None, "pronoun"),
    CaptchaStory("Ava", "nurse", False, "cat", "Sunny", None, "pronoun"),
    CaptchaStory("Ethan", "software architect", True, "cat", "Clover", None, "pronoun"),
    CaptchaStory("Sophia", "baker", False, "cat", "Pebble", None, "pronoun"),
    CaptchaStory("Liam", "paramedic", True, "cat", "Smokey", None, "pronoun"),
    CaptchaStory("Isabella", "journalist", False, "cat", "Luna", None, "pronoun"),
    CaptchaStory("Mason", "carpenter", True, "cat", "Tiger", None, "pronoun"),
    CaptchaStory("Anya", "interpreter", False, "cat", "Pushok", None, "pronoun"),
    CaptchaStory("Dmitri", "aerospace engineer", True, "cat", "Barsik", None, "pronoun"),
    CaptchaStory("Elena", "doctor", False, "cat", "Sneg", None, "pronoun"),
    CaptchaStory("Nikolai", "history professor", True, "cat", "Murzik", None, "pronoun"),
    CaptchaStory("Irina", "pianist", False, "cat", "Mishka", None, "pronoun"),
    CaptchaStory("Sergei", "marine biologist", True, "cat", "Ryzhik", None, "pronoun"),
    CaptchaStory("Tatiana", "architect", False, "cat", "Zvezda", None, "pronoun"),
    CaptchaStory("Alexei", "journalist", True, "cat", "Kotya", "he", "pronoun"),
    CaptchaStory("Yulia", "theatre director", False, "cat", "Lapka", None, "pronoun"),
    CaptchaStory("Mikhail", "chef", True, "cat", "Tuman", None, "pronoun"),
    CaptchaStory("Hyeri", "illustrator", False, "dog", "Gureum", None, "species"),
    CaptchaStory("Brandon", "park ranger", True, "dog", "Buddy", None, "species"),
    CaptchaStory("Oksana", "music teacher", False, "dog", "Volna", None, "species"),
)


PRONOUN_PATTERN = re.compile(
    r"^(?P<person>[A-Za-z]+) is a (?P<descriptor>.+?) who has a (?P<species>\w+) named (?P<pet>[^.]+)\. \"(?P<quoted>[^\"]+)\" "
    r"is adorable\. Answer what the double-quoted text refers to\.$"
)

SPECIES_PATTERN = re.compile(
    r"^(?P<person>[A-Za-z]+) is a (?P<descriptor>.+?) who has a (?P<species>\w+) named (?P<pet>[^.]+)\. "
    r"What kind of pet does (?P=person) have\? Answer in lowercase\.$"
)


def _lookup_story(person: str, pet: str) -> Optional[CaptchaStory]:
    for story in CAPTCHA_STORIES:
        if story.person_name == person and story.pet_name == pet:
            return story
    return None


def solve_captcha(question: str) -> Optional[str]:
    """Derive the captcha answer directly from the prompt text."""

    question = question.strip()
    pronoun_match = PRONOUN_PATTERN.match(question)
    if pronoun_match:
        person = pronoun_match.group("person")
        descriptor = pronoun_match.group("descriptor")
        species = pronoun_match.group("species")
        pet = pronoun_match.group("pet")
        quoted = pronoun_match.group("quoted").strip().lower()

        story = _lookup_story(person, pet)
        if story is None:
            return None

        person_pronoun = "he" if story.is_male else "she"
        pet_pronoun = (story.pet_pronoun or "it").lower()

        descriptor_token = f"the {descriptor.lower()}"
        species_token = f"the {species.lower()}"

        if quoted == pet_pronoun or quoted == species_token:
            return story.pet_name
        if quoted == person_pronoun or quoted == descriptor_token:
            return story.person_name

        # When pronouns collide (e.g. both "he"), prefer the pet if the
        # descriptor token matches the person.  Otherwise fall back to the
        # person.
        if quoted == species_token.rstrip("s"):
            return story.pet_name
        return story.person_name if quoted == descriptor.lower() else story.pet_name

    species_match = SPECIES_PATTERN.match(question)
    if species_match:
        person = species_match.group("person")
        pet = species_match.group("pet")
        story = _lookup_story(person, pet)
        if story is None:
            return None
        return story.pet_species.lower()

    return None


# --- Self-test helpers -------------------------------------------------------------------------

def _format_pronoun_prompt(story: CaptchaStory, refer_pet: bool, use_pronoun: bool) -> Tuple[str, str]:
    person_pronoun = "he" if story.is_male else "she"
    pet_pronoun = story.pet_pronoun or "it"
    if use_pronoun:
        quoted = pet_pronoun if refer_pet else person_pronoun
    else:
        quoted = f"the {story.pet_species}" if refer_pet else f"the {story.descriptor}"
    answer = story.pet_name if refer_pet else story.person_name
    question = (
        f"{story.person_name} is a {story.descriptor} who has a {story.pet_species} named {story.pet_name}. "
        f"\"{quoted}\" is adorable. Answer what the double-quoted text refers to."
    )
    return question, answer


def _format_species_prompt(story: CaptchaStory) -> Tuple[str, str]:
    question = (
        f"{story.person_name} is a {story.descriptor} who has a {story.pet_species} named {story.pet_name}. "
        f"What kind of pet does {story.person_name} have? Answer in lowercase."
    )
    answer = story.pet_species.lower()
    return question, answer


def run_captcha_self_test() -> int:
    """Verify the solver matches every captcha prompt used by the server."""

    question_answers: Dict[str, Set[str]] = defaultdict(set)
    for story in CAPTCHA_STORIES:
        if story.template_type == "pronoun":
            for refer_pet in (False, True):
                for use_pronoun in (False, True):
                    question, expected = _format_pronoun_prompt(story, refer_pet, use_pronoun)
                    question_answers[question].add(expected)
        else:
            question, expected = _format_species_prompt(story)
            question_answers[question].add(expected)

    failures: List[str] = []
    ambiguous: List[str] = []
    for question, answers in question_answers.items():
        observed = solve_captcha(question)
        if observed is None or observed not in answers:
            expected_str = ", ".join(sorted(answers))
            failures.append(
                f"expected one of {{{expected_str}}} but solver returned {observed!r} for question '{question}'"
            )
        if len(answers) > 1:
            ambiguous.append(question)

    if failures:
        print("captcha self-test failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1

    if ambiguous:
        print("captcha self-test passed; ambiguous prompts were resolved using deterministic tie-breakers.")
        for question in ambiguous:
            choices = ", ".join(sorted(question_answers[question]))
            observed = solve_captcha(question)
            print(f" - '{question}' → accepted answers {{{choices}}}, solver chose '{observed}'")
        return 0

    print("captcha self-test passed for all known prompts.")
    return 0


# --- Chat configuration ------------------------------------------------------------------------

def _get_env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


DEFAULT_SYSTEM_PROMPT = (
    "You are ChatGPT 5, a friendly and lawful participant in the ssh-chatter room. "
    "Answer succinctly, follow U.S. law, refuse disallowed or dangerous requests, "
    "and keep the conversation welcoming."
)

DEFAULT_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
DEFAULT_HISTORY_LIMIT = _get_env_int("GPT_HISTORY_LIMIT", 12)
DEFAULT_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com")
DEFAULT_RESPONSE_COOLDOWN = _get_env_float("GPT_RESPONSE_COOLDOWN", 2.0)
DEFAULT_MEMORY_MAX_ENTRIES = _get_env_int("GPT_MEMORY_MAX", 200)
DEFAULT_MEMORY_RECALL = _get_env_int("GPT_MEMORY_RECALL", 3)
DEFAULT_MEMORY_MIN_LENGTH = _get_env_int("GPT_MEMORY_MIN_LENGTH", 4)


# --- Moderation policy -------------------------------------------------------------------------

UNETHICAL_KEYWORDS: Tuple[str, ...] = (
    "hate",
    "racist",
    "sexist",
    "slur",
    "harass",
    "harassment",
    "violence",
    "violent",
    "extremist",
    "genocide",
    "abuse",
    "abusive",
    "bigot",
    "bigotry",
    "terror",
    "terrorist",
)

CRIMINAL_KEYWORDS: Tuple[str, ...] = (
    "bomb",
    "weapon",
    "explosive",
    "murder",
    "kill",
    "killing",
    "kidnap",
    "kidnapping",
    "assassin",
    "shoot",
    "shooting",
    "arson",
    "traffick",
    "terrorism",
    "extortion",
    "fraud",
)


@dataclass
class ModerationConfig:
    warning_limit: int = 5
    warning_ttl: float = 3600.0  # seconds before warnings expire
    unethical_keywords: Tuple[str, ...] = UNETHICAL_KEYWORDS
    criminal_keywords: Tuple[str, ...] = CRIMINAL_KEYWORDS


@dataclass
class WarningRecord:
    count: int = 0
    last_timestamp: float = field(default_factory=time.time)


@dataclass
class ChatConfig:
    model: str = DEFAULT_MODEL
    history_limit: int = DEFAULT_HISTORY_LIMIT
    system_prompt: str = DEFAULT_SYSTEM_PROMPT
    api_key: Optional[str] = None
    base_url: str = DEFAULT_BASE_URL
    respond_to_questions: bool = False
    response_cooldown: float = DEFAULT_RESPONSE_COOLDOWN
    memory_path: Optional[str] = os.environ.get("GPT_MEMORY_PATH")
    memory_max_entries: int = DEFAULT_MEMORY_MAX_ENTRIES
    memory_recall: int = DEFAULT_MEMORY_RECALL
    memory_min_length: int = DEFAULT_MEMORY_MIN_LENGTH


class SimpleMemoryStore:
    """Naive keyword-based memory for lightweight retrieval augmentation."""

    def __init__(
        self,
        *,
        path: Optional[str],
        max_entries: int,
        recall: int,
        min_length: int,
    ) -> None:
        self._enabled = bool(path)
        self._path = path
        self._max_entries = max(1, max_entries)
        self._recall = max(1, recall)
        self._min_length = max(1, min_length)
        self._entries: List[Dict[str, Any]] = []
        if self._enabled:
            self._load()

    @staticmethod
    def _extract_keywords(text: str, min_length: int) -> Set[str]:
        tokens = re.findall(r"[A-Za-z0-9']+", text.lower())
        return {token for token in tokens if len(token) >= min_length}

    def _load(self) -> None:
        if not self._path:
            return
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return
        except Exception as exc:  # pragma: no cover - file corruption
            logging.warning("unable to load memory store %s: %s", self._path, exc)
            return

        if not isinstance(data, list):
            logging.warning("memory store %s is not a list; ignoring", self._path)
            return

        now = time.time()
        for entry in data:
            text = entry.get("text") if isinstance(entry, dict) else None
            if not text or not isinstance(text, str):
                continue
            keywords = entry.get("keywords") if isinstance(entry, dict) else None
            if not isinstance(keywords, list):
                keywords = list(self._extract_keywords(text, self._min_length))
            timestamp = entry.get("timestamp") if isinstance(entry, dict) else None
            if not isinstance(timestamp, (int, float)):
                timestamp = now
            self._entries.append(
                {
                    "text": text,
                    "keywords": {str(k) for k in keywords},
                    "timestamp": float(timestamp),
                }
            )
        if len(self._entries) > self._max_entries:
            self._entries = self._entries[-self._max_entries :]

    def _persist(self) -> None:
        if not self._path:
            return
        directory = os.path.dirname(self._path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        serialisable = [
            {
                "text": entry["text"],
                "keywords": sorted(entry["keywords"]),
                "timestamp": entry["timestamp"],
            }
            for entry in self._entries[-self._max_entries :]
        ]
        tmp_path = f"{self._path}.tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(serialisable, fh, ensure_ascii=False, indent=2)
            os.replace(tmp_path, self._path)
        except OSError as exc:  # pragma: no cover - filesystem issues
            logging.warning("unable to persist memory store %s: %s", self._path, exc)
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    def remember(self, text: str) -> None:
        if not self._enabled:
            return
        cleaned = text.strip()
        if not cleaned:
            return
        keywords = self._extract_keywords(cleaned, self._min_length)
        if not keywords:
            return
        timestamp = time.time()
        self._entries.append(
            {"text": cleaned, "keywords": keywords, "timestamp": timestamp}
        )
        if len(self._entries) > self._max_entries:
            self._entries = self._entries[-self._max_entries :]
        self._persist()

    def retrieve(self, query: str) -> List[str]:
        if not self._enabled:
            return []
        keywords = self._extract_keywords(query, self._min_length)
        if not keywords:
            return []
        scored: List[Tuple[int, float, str]] = []
        for entry in self._entries:
            overlap = len(keywords.intersection(entry["keywords"]))
            if overlap == 0:
                continue
            scored.append((overlap, entry["timestamp"], entry["text"]))
        scored.sort(key=lambda item: (-item[0], -item[1]))
        return [text for _, _, text in scored[: self._recall]]

    @property
    def enabled(self) -> bool:
        return self._enabled


class ModerationEngine:
    """Track moderation warnings and determine escalation paths."""

    def __init__(self, config: ModerationConfig) -> None:
        self._config = config
        self._warnings: Dict[str, WarningRecord] = {}

    def register_message(self, username: str, message: str) -> Optional[Tuple[str, str]]:
        """Return a tuple describing the violation (severity, keyword)."""

        lowered = message.lower()
        for keyword in self._config.criminal_keywords:
            if keyword in lowered:
                return ("criminal", keyword)
        for keyword in self._config.unethical_keywords:
            if keyword in lowered:
                return ("unethical", keyword)
        return None

    def increment_warning(self, username: str) -> int:
        now = time.time()
        record = self._warnings.get(username)
        if record is None:
            record = WarningRecord(count=1, last_timestamp=now)
            self._warnings[username] = record
            return record.count

        if now - record.last_timestamp > self._config.warning_ttl:
            record.count = 0
        record.count += 1
        record.last_timestamp = now
        return record.count

    def clear(self, username: str) -> None:
        self._warnings.pop(username, None)


class OpenAIChatResponder:
    """Thin wrapper around the OpenAI chat completions API."""

    def __init__(self, model: str, api_key: str, base_url: str, *, timeout: float = 30.0) -> None:
        self._model = model
        self._api_key = api_key
        self._base_url = base_url.rstrip("/") or "https://api.openai.com"
        self._timeout = timeout

    def _complete(self, messages: List[Dict[str, str]]) -> str:
        payload = json.dumps({"model": self._model, "messages": messages}).encode("utf-8")
        url = f"{self._base_url}/v1/chat/completions"
        req = urllib_request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self._api_key}")

        try:
            with urllib_request.urlopen(req, timeout=self._timeout) as response:
                body = response.read()
        except urllib_error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "ignore") if exc.fp else exc.reason
            raise RuntimeError(f"OpenAI request failed with status {exc.code}: {detail}") from exc
        except urllib_error.URLError as exc:
            raise RuntimeError(f"OpenAI request failed: {exc.reason}") from exc

        parsed = json.loads(body.decode("utf-8"))
        choices = parsed.get("choices")
        if not choices:
            raise RuntimeError("OpenAI response did not include choices")

        message = choices[0].get("message", {}).get("content")
        if not message:
            raise RuntimeError("OpenAI response did not include message content")

        return message.strip()

    async def generate_reply(self, messages: List[Dict[str, str]]) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._complete, messages)


# --- SSH chat client ---------------------------------------------------------------------------

CHAT_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"^\[([^\]]+)\]\s+(.*)$"),
    re.compile(r"^<([^>]+)>\s+(.*)$"),
    re.compile(r"^([^:]+):\s+(.*)$"),
)


DEFAULT_SSH_PORT = 2022


def _parse_host_port(raw_value: str) -> Tuple[str, Optional[int]]:
    """Extract host and optional port from a variety of input formats."""

    text = raw_value.strip()
    if not text:
        return text, None

    comma_match = re.match(r"^\s*([^,\s]+)\s*,\s*(?:port\s*)?(\d+)\s*$", text, re.IGNORECASE)
    if comma_match:
        return comma_match.group(1), int(comma_match.group(2))

    word_match = re.match(r"^\s*([^\s]+)\s+port\s+(\d+)\s*$", text, re.IGNORECASE)
    if word_match:
        return word_match.group(1), int(word_match.group(2))

    if text.startswith("[") and "]" in text:
        closing = text.index("]")
        host_part = text[1:closing]
        rest = text[closing + 1 :].strip()
        if rest.startswith(":") and rest[1:].isdigit():
            return host_part, int(rest[1:])
        return host_part, None

    if ":" in text and text.count(":") == 1:
        host_part, port_part = text.rsplit(":", 1)
        if port_part.isdigit():
            return host_part, int(port_part)

    parsed = urlparse(text if "://" in text else f"ssh://{text}")
    host = parsed.hostname or text
    port = parsed.port
    return host, port


@dataclass
class BotConfig:
    host: str
    port: int
    username: str
    password: Optional[str]
    identity: Optional[str]
    reconnect_delay: float
    moderation: ModerationConfig
    chat: ChatConfig
    announce: bool = True


class GPTModeratorBot:
    """Autonomous moderator that connects to ssh-chatter via SSH."""

    def __init__(self, config: BotConfig, ssh_module: Any) -> None:
        self._config = config
        self._engine = ModerationEngine(config.moderation)
        self._running = True
        self._joined = False
        self._captcha_question: Optional[str] = None
        self._announced = False
        self._ssh = ssh_module
        self._connection: Optional[Any] = None
        self._process: Optional[Any] = None
        self._chat_history: List[Dict[str, str]] = []
        self._system_message = {"role": "system", "content": config.chat.system_prompt}
        self._memory = SimpleMemoryStore(
            path=config.chat.memory_path,
            max_entries=config.chat.memory_max_entries,
            recall=config.chat.memory_recall,
            min_length=config.chat.memory_min_length,
        )
        self._responder: Optional[OpenAIChatResponder] = None
        self._last_response_ts = 0.0

        if config.chat.api_key:
            self._responder = OpenAIChatResponder(
                config.chat.model,
                config.chat.api_key,
                config.chat.base_url,
            )
        else:
            logging.warning("OPENAI_API_KEY not configured; GPT responses disabled.")

        if self._memory.enabled:
            logging.info(
                "RAG memory enabled (%d entries, recalling %d) at %s",
                config.chat.memory_max_entries,
                config.chat.memory_recall,
                config.chat.memory_path,
            )

    async def run(self) -> None:
        while self._running:
            try:
                await self._connect_and_moderate()
            except (self._ssh.Error, OSError) as exc:
                logging.error("connection failure: %s", exc)
                await asyncio.sleep(self._config.reconnect_delay)

    async def _connect_and_moderate(self) -> None:
        logging.info("connecting to %s:%s as %s", self._config.host, self._config.port, self._config.username)
        async with self._ssh.connect(
            self._config.host,
            port=self._config.port,
            username=self._config.username,
            password=self._config.password,
            client_keys=[self._config.identity] if self._config.identity else None,
            known_hosts=None,
        ) as connection:
            self._connection = connection
            self._engine = ModerationEngine(self._config.moderation)
            self._joined = False
            self._announced = False
            self._captcha_question = None
            self._reset_conversation()

            process = await connection.create_process(term_type="xterm-256color")
            self._process = process
            stderr_task = asyncio.create_task(self._log_stderr(process))
            stdout_task = asyncio.create_task(self._read_stdout(process))

            done, pending = await asyncio.wait(
                {stderr_task, stdout_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            await asyncio.gather(*done, return_exceptions=True)

    def _reset_conversation(self) -> None:
        self._chat_history.clear()
        self._last_response_ts = 0.0

    def _append_history(self, role: str, content: str) -> None:
        self._chat_history.append({"role": role, "content": content})
        self._trim_history()

    def _trim_history(self) -> None:
        max_entries = max(self._config.chat.history_limit * 2, 2)
        if len(self._chat_history) > max_entries:
            self._chat_history = self._chat_history[-max_entries:]

    def _build_messages(self) -> List[Dict[str, str]]:
        return [self._system_message, *self._chat_history]

    def _should_respond(self, username: str, message: str) -> bool:
        if self._responder is None:
            return False
        if not self._joined:
            return False
        stripped = message.strip()
        if not stripped or stripped.startswith("/"):
            return False

        now = time.time()
        if now - self._last_response_ts < self._config.chat.response_cooldown:
            return False

        lowered = stripped.lower()
        bot_name = self._config.username.lower()
        if bot_name in lowered:
            return True
        if lowered.startswith("gpt") or lowered.startswith("@gpt"):
            return True
        if self._config.chat.respond_to_questions and stripped.endswith("?"):
            return True
        return False

    async def _respond_to_message(self, username: str, message: str) -> None:
        if self._responder is None:
            return

        user_entry = f"{username}: {message}"
        self._append_history("user", user_entry)

        memory_context = self._memory.retrieve(message)
        messages = self._build_messages()
        if memory_context:
            memory_block = "Relevant saved notes:\n" + "\n".join(
                f"- {item}" for item in memory_context
            )
            messages = [messages[0], {"role": "system", "content": memory_block}, *messages[1:]]

        try:
            reply = await self._responder.generate_reply(messages)
        except Exception as exc:  # pragma: no cover - network/HTTP exceptions
            logging.error("failed to generate GPT reply: %s", exc)
            if self._chat_history and self._chat_history[-1]["content"] == user_entry:
                self._chat_history.pop()
            return

        reply = reply.strip()
        if not reply:
            if self._chat_history and self._chat_history[-1]["content"] == user_entry:
                self._chat_history.pop()
            return

        self._append_history("assistant", reply)
        self._memory.remember(user_entry)
        self._memory.remember(f"{self._config.username}: {reply}")
        self._last_response_ts = time.time()
        await self._send(reply)

    async def _log_stderr(self, process: Any) -> None:
        async for line in process.stderr:
            text = line.rstrip("\n")
            logging.debug("stderr: %s", text)

    async def _read_stdout(self, process: Any) -> None:
        async for line in process.stdout:
            text = line.rstrip("\n")
            await self._handle_line(text)

    async def _handle_line(self, line: str) -> None:
        stripped = line.strip()
        if not stripped:
            return

        logging.debug("server: %s", stripped)

        if stripped.startswith("Before entering the room"):
            self._captcha_question = None
            return

        if "Answer what the double-quoted text refers to." in stripped or "Answer in lowercase." in stripped:
            self._captcha_question = stripped
            return

        if stripped.startswith("Type your answer") and self._captcha_question:
            answer = solve_captcha(self._captcha_question)
            if answer is None:
                logging.error("unable to solve captcha question: %s", self._captcha_question)
                # Send an empty response so the server can react (usually by
                # issuing a new captcha or disconnecting us) and stop the bot
                # to avoid spamming incorrect answers.
                await self._submit_captcha_answer("")
                self.stop()
            else:
                await self._submit_captcha_answer(answer)
            self._captcha_question = None
            return

        if "Captcha solved" in stripped or stripped.startswith("* You are now chatting"):
            if not self._joined:
                self._reset_conversation()
            self._joined = True

        if self._config.username in stripped and "has joined the chat" in stripped:
            if not self._joined:
                self._reset_conversation()
            self._joined = True

        if self._joined and self._config.announce and not self._announced:
            await self._send("Hello! I'm ChatGPT 5. Mention me or ask a question and I'll reply.")
            self._announced = True

        parsed = self._parse_chat_line(stripped)
        if parsed is None:
            return

        username, message = parsed
        if username.lower() == self._config.username.lower():
            return

        violation = self._engine.register_message(username, message)
        if violation is not None:
            severity, keyword = violation
            if severity == "criminal":
                await self._handle_criminal(username, keyword)
            else:
                await self._handle_unethical(username, keyword)
            return

        if self._should_respond(username, message):
            await self._respond_to_message(username, message)

    @staticmethod
    def _parse_chat_line(line: str) -> Optional[Tuple[str, str]]:
        if line.startswith("*"):
            return None
        for pattern in CHAT_PATTERNS:
            match = pattern.match(line)
            if match:
                user = match.group(1).strip()
                message = match.group(2).strip()
                if user and message:
                    return user, message
        return None

    async def _handle_unethical(self, username: str, keyword: str) -> None:
        warnings = self._engine.increment_warning(username)
        warning_message = (
            f"/pm {username} ⚠️ Please avoid unethical language (triggered by '{keyword}'). "
            f"Warning {warnings}/{self._config.moderation.warning_limit}."
        )
        await self._send(warning_message)
        if warnings >= self._config.moderation.warning_limit:
            await self._send(f"/kick {username} repeated unethical behaviour after {warnings} warnings.")
            self._engine.clear(username)

    async def _handle_criminal(self, username: str, keyword: str) -> None:
        await self._send(
            f"/pm {username} 🚫 Criminal discussions are prohibited under U.S. law. "
            f"(triggered by '{keyword}')."
        )
        await self._send(f"/ban {username} criminal content (keyword: {keyword}).")
        self._engine.clear(username)

    async def _send(self, message: str) -> None:
        if not self._process:
            return
        logging.info("send: %s", message)
        self._process.stdin.write(message + "\n")
        await self._process.stdin.drain()

    async def _submit_captcha_answer(self, answer: str) -> None:
        if not self._process:
            return
        logging.info("captcha answer: %s", answer)
        self._process.stdin.write(answer)
        self._process.stdin.write("\n")
        await self._process.stdin.drain()

    def stop(self) -> None:
        self._running = False
        if self._process is not None:
            self._process.stdin.write("/exit\n")


# --- Command-line interface -------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Autonomous ChatGPT 5 moderator for ssh-chatter"
    )
    parser.add_argument("host", nargs="?", help="ssh-chatter host to connect to")
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="SSH port (defaults to 2022 or a value embedded in the host)",
    )
    parser.add_argument("--username", default="gpt-5", help="login username (default: gpt-5)")
    parser.add_argument("--password", default=None, help="login password, if required")
    parser.add_argument("--identity", default=None, help="path to a private key for public-key auth")
    parser.add_argument("--reconnect-delay", type=float, default=5.0, help="seconds between reconnect attempts")
    parser.add_argument(
        "--warning-limit",
        type=int,
        default=5,
        help="number of warnings before a user is kicked (default: 5)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="logging verbosity",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="verify captcha solving against all known prompts and exit",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="OpenAI model to use for chat replies (default from OPENAI_MODEL or gpt-4o-mini)",
    )
    parser.add_argument(
        "--history-limit",
        type=int,
        default=DEFAULT_HISTORY_LIMIT,
        help="number of recent exchanges to keep in GPT context",
    )
    parser.add_argument(
        "--system-prompt",
        default=None,
        help="override the GPT system prompt (or set GPT_PROMPT env)",
    )
    parser.add_argument(
        "--openai-api-key",
        default=None,
        help="OpenAI API key (overrides OPENAI_API_KEY env variable)",
    )
    parser.add_argument(
        "--openai-base-url",
        default=DEFAULT_BASE_URL,
        help="Base URL for OpenAI-compatible APIs (default from OPENAI_BASE_URL)",
    )
    parser.add_argument(
        "--respond-to-questions",
        action="store_true",
        help="respond to any question even without being mentioned",
    )
    parser.add_argument(
        "--response-cooldown",
        type=float,
        default=DEFAULT_RESPONSE_COOLDOWN,
        help="minimum seconds between GPT replies",
    )
    parser.add_argument(
        "--memory-path",
        default=None,
        help="path to a JSON file for persistent GPT memory (or set GPT_MEMORY_PATH)",
    )
    parser.add_argument(
        "--memory-max-entries",
        type=int,
        default=DEFAULT_MEMORY_MAX_ENTRIES,
        help="maximum number of saved memory entries",
    )
    parser.add_argument(
        "--memory-recall",
        type=int,
        default=DEFAULT_MEMORY_RECALL,
        help="maximum number of memory snippets to inject",
    )
    parser.add_argument(
        "--memory-min-length",
        type=int,
        default=DEFAULT_MEMORY_MIN_LENGTH,
        help="minimum keyword length for memory matching",
    )
    parser.add_argument(
        "--disable-memory",
        action="store_true",
        help="skip loading or saving persistent GPT memory",
    )
    return parser


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


async def main_async(args: argparse.Namespace) -> None:
    configure_logging(args.log_level)
    ssh_module = importlib.import_module("asyncssh")
    system_prompt = args.system_prompt or os.environ.get("GPT_PROMPT") or DEFAULT_SYSTEM_PROMPT
    api_key = args.openai_api_key or os.environ.get("OPENAI_API_KEY")
    respond_to_questions = args.respond_to_questions
    if not respond_to_questions:
        env_flag = os.environ.get("GPT_RESPOND_TO_QUESTIONS")
        if env_flag and env_flag.lower() in {"1", "true", "yes", "on"}:
            respond_to_questions = True
    memory_path = args.memory_path or os.environ.get("GPT_MEMORY_PATH")
    if args.disable_memory:
        memory_path = None
    config = BotConfig(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        identity=args.identity,
        reconnect_delay=args.reconnect_delay,
        moderation=ModerationConfig(warning_limit=args.warning_limit),
        chat=ChatConfig(
            model=args.model,
            history_limit=args.history_limit,
            system_prompt=system_prompt,
            api_key=api_key,
            base_url=args.openai_base_url,
            respond_to_questions=respond_to_questions,
            response_cooldown=args.response_cooldown,
            memory_path=memory_path,
            memory_max_entries=max(1, args.memory_max_entries),
            memory_recall=max(1, args.memory_recall),
            memory_min_length=max(1, args.memory_min_length),
        ),
    )
    bot = GPTModeratorBot(config, ssh_module)

    loop = asyncio.get_running_loop()

    def _stop(*_ignored: object) -> None:
        logging.info("shutdown requested")
        bot.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _stop)

    await bot.run()


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.self_test:
        return run_captcha_self_test()

    env_host = os.environ.get("CHATTER_HOST")
    if not args.host and env_host:
        args.host = env_host

    if not args.host:
        parser.error("host is required unless --self-test is used")

    args.host, embedded_port = _parse_host_port(args.host)

    if args.port is None:
        env_port = os.environ.get("CHATTER_PORT")
        if env_port:
            try:
                args.port = int(env_port)
            except ValueError:
                parser.error("CHATTER_PORT must be an integer")
        elif embedded_port is not None:
            args.port = embedded_port
        else:
            args.port = DEFAULT_SSH_PORT

    if args.port <= 0:
        parser.error("port must be a positive integer")

    if args.username == parser.get_default("username"):
        env_username = os.environ.get("CHATTER_USERNAME")
        if env_username:
            args.username = env_username

    if args.password is None:
        env_password = os.environ.get("CHATTER_PASSWORD")
        if env_password:
            args.password = env_password

    if args.identity is None:
        env_identity = os.environ.get("CHATTER_IDENTITY")
        if env_identity:
            args.identity = env_identity

    if args.warning_limit == parser.get_default("warning_limit"):
        env_warning_limit = os.environ.get("CHATTER_WARNING_LIMIT")
        if env_warning_limit:
            try:
                args.warning_limit = int(env_warning_limit)
            except ValueError:
                parser.error("CHATTER_WARNING_LIMIT must be an integer")

    if args.log_level == parser.get_default("log_level"):
        env_log_level = os.environ.get("CHATTER_LOG_LEVEL")
        if env_log_level:
            args.log_level = env_log_level

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        logging.info("interrupted by user")
    return 0


if __name__ == "__main__":
    sys.exit(main())
