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
import logging
import re
import signal
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


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


# --- SSH chat client ---------------------------------------------------------------------------

CHAT_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"^\[([^\]]+)\]\s+(.*)$"),
    re.compile(r"^<([^>]+)>\s+(.*)$"),
    re.compile(r"^([^:]+):\s+(.*)$"),
)


@dataclass
class BotConfig:
    host: str
    port: int
    username: str
    password: Optional[str]
    identity: Optional[str]
    reconnect_delay: float
    moderation: ModerationConfig
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
                await self._send("")
                self.stop()
            else:
                await self._send(answer)
            self._captcha_question = None
            return

        if "Captcha solved" in stripped or stripped.startswith("* You are now chatting"):
            self._joined = True

        if self._config.username in stripped and "has joined the chat" in stripped:
            self._joined = True

        if self._joined and self._config.announce and not self._announced:
            await self._send("Hello! I am the GPT moderator bot. Behave responsibly.")
            self._announced = True

        parsed = self._parse_chat_line(stripped)
        if parsed is None:
            return

        username, message = parsed
        if username.lower() == self._config.username.lower():
            return

        violation = self._engine.register_message(username, message)
        if violation is None:
            return

        severity, keyword = violation
        if severity == "criminal":
            await self._handle_criminal(username, keyword)
        else:
            await self._handle_unethical(username, keyword)

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

    def stop(self) -> None:
        self._running = False
        if self._process is not None:
            self._process.stdin.write("/exit\n")


# --- Command-line interface -------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Autonomous GPT moderator for ssh-chatter")
    parser.add_argument("host", nargs="?", help="ssh-chatter host to connect to")
    parser.add_argument("--port", type=int, default=2022, help="SSH port (default: 2022)")
    parser.add_argument("--username", default="gpt", help="login username (default: gpt)")
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
    return parser


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


async def main_async(args: argparse.Namespace) -> None:
    configure_logging(args.log_level)
    ssh_module = importlib.import_module("asyncssh")
    config = BotConfig(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        identity=args.identity,
        reconnect_delay=args.reconnect_delay,
        moderation=ModerationConfig(warning_limit=args.warning_limit),
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
    if not args.host:
        parser.error("host is required unless --self-test is used")
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        logging.info("interrupted by user")
    return 0


if __name__ == "__main__":
    sys.exit(main())
