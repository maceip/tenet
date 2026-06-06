"""Dependency-free terminal polish for the product CLI.

The display layer is deliberately separate from protocol code. It can be
replaced by a richer renderer later while keeping stdout/json behavior stable.
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
from typing import IO, Mapping, Sequence
from urllib.parse import urlparse


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
MAGENTA = "\033[35m"
RED = "\033[31m"
YELLOW = "\033[33m"
CLEAR_LINE = "\033[2K"
HOME = "\033[H"
CLEAR_SCREEN = "\033[2J"
HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"
CLI_UI_TODO_MARKER = "CLI_UI_TODO"


def terminal_supports_ansi(stream: IO[str]) -> bool:
    """Return true when ANSI color/status updates are likely to render cleanly."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    is_tty = getattr(stream, "isatty", lambda: False)
    if not is_tty():
        return False
    if os.name == "nt":
        return _enable_windows_virtual_terminal(stream)
    return True


def should_show_interactive_display(stream: IO[str], *, plain: bool = False) -> bool:
    return not plain and terminal_supports_ansi(stream)


def _enable_windows_virtual_terminal(stream: IO[str]) -> bool:
    """Best-effort enablement for Windows 10+ ANSI handling."""
    try:
        import ctypes
        from ctypes import wintypes

        handle_name = "STD_ERROR_HANDLE" if stream is sys.stderr else "STD_OUTPUT_HANDLE"
        handle_id = -12 if handle_name == "STD_ERROR_HANDLE" else -11
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(handle_id)
        if handle in (0, -1):
            return False
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(
            kernel32.SetConsoleMode(
                handle,
                mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
            )
        )
    except Exception:
        return False


@dataclass(frozen=True)
class AskNetworkDisplay:
    matcher_host: str
    value_x_prefix: str
    relay_id: str
    relay_endpoint: str
    relay_count: int
    route_mode: str

    @classmethod
    def from_join_pack(
        cls,
        matcher: Mapping[str, object],
        reachability_relay: Mapping[str, object],
        *,
        relay_count: int,
        route_mode: str,
    ) -> "AskNetworkDisplay":
        url = str(matcher.get("url", ""))
        parsed = urlparse(url)
        value_x = _first_string(matcher.get("approved_value_x"))
        relay_id = str(reachability_relay.get("relay_id", "reachability-relay"))
        relay_host = str(reachability_relay.get("host", "unknown"))
        relay_port = str(reachability_relay.get("port", ""))
        return cls(
            matcher_host=parsed.netloc or url.rstrip("/") or "attested matcher",
            value_x_prefix=value_x[:12] if value_x else "unpinned",
            relay_id=relay_id,
            relay_endpoint=f"{relay_host}:{relay_port}" if relay_port else relay_host,
            relay_count=relay_count,
            route_mode=route_mode,
        )


class AskDisplay:
    """TTY-only product display for ``tenet ask``."""

    def __init__(
        self,
        network: AskNetworkDisplay,
        *,
        stream: IO[str] = sys.stderr,
        enabled: bool = True,
    ) -> None:
        self.network = network
        self.stream = stream
        self.enabled = enabled

    def start(self) -> "StatusRail":
        if not self.enabled:
            return StatusRail.disabled()

        self._line(f"{BOLD}{CYAN}tenet live network{RESET}")
        self._line(
            f"{DIM}trust{RESET}  attested matcher {self.network.matcher_host}  "
            f"value_x={self.network.value_x_prefix}..."
        )
        self._line(
            f"{DIM}route{RESET}  you -> matcher -> {self.network.relay_id} "
            f"({self.network.relay_endpoint}) -> expert"
        )
        self._line(
            f"{DIM}peers{RESET}  {self.network.relay_count} trusted relay(s), "
            f"mode={self.network.route_mode}"
        )
        self._line("")
        rail = StatusRail(
            "attesting enclave, matching expertise, and opening return path",
            stream=self.stream,
        )
        rail.start()
        return rail

    def finish(self, result: Mapping[str, object]) -> None:
        if not self.enabled:
            return
        ok = bool(result.get("ok"))
        selected = str(result.get("selected_peer_id") or "none")
        via_mailbox = bool(result.get("via_mailbox"))
        degraded = bool(result.get("degraded_anonymity"))
        color = GREEN if ok else RED
        state = "ready" if ok else "failed"
        warn = f" {YELLOW}degraded_pool{RESET}" if degraded else ""
        self._line(
            f"{color}{state}{RESET}  selected={selected} "
            f"via_mailbox={str(via_mailbox).lower()}{warn}"
        )
        self._line("")

    def _line(self, text: str) -> None:
        print(text, file=self.stream, flush=True)


@dataclass(frozen=True)
class ServiceCard:
    name: str
    state: str
    detail: str
    badge: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class DashboardSnapshot:
    title: str
    network: AskNetworkDisplay
    services: tuple[ServiceCard, ...]
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "title": self.title,
            "network": asdict(self.network),
            "services": [service.to_dict() for service in self.services],
            "notes": list(self.notes),
        }


class DashboardDisplay:
    """One-screen operator dashboard for the current network stack."""

    def __init__(
        self,
        *,
        stream: IO[str] = sys.stdout,
        enabled: bool = True,
        width: int | None = None,
    ) -> None:
        self.stream = stream
        self.enabled = enabled
        self.width = width

    def render(self, snapshot: DashboardSnapshot) -> str:
        width = max(72, min(self.width or shutil.get_terminal_size((96, 30)).columns, 118))
        if not self.enabled:
            return self._render_plain(snapshot)

        scene = TerminalSceneRenderer().render_network_scene(snapshot.network, width=width)
        lines = [
            f"{BOLD}{CYAN}{snapshot.title}{RESET}",
            f"{DIM}{'=' * min(width, len(snapshot.title))}{RESET}",
            scene,
            self._service_grid(snapshot.services, width=width),
        ]
        if snapshot.notes:
            lines.append(f"{DIM}notes{RESET}")
            lines.extend(f"  - {note}" for note in snapshot.notes)
        return "\n".join(lines).rstrip() + "\n"

    def print(self, snapshot: DashboardSnapshot) -> None:
        self.stream.write(self.render(snapshot))
        self.stream.flush()

    def _render_plain(self, snapshot: DashboardSnapshot) -> str:
        lines = [snapshot.title, "-" * len(snapshot.title)]
        lines.append(
            "route: you -> matcher "
            f"{snapshot.network.matcher_host} -> relay {snapshot.network.relay_id} "
            f"({snapshot.network.relay_endpoint}) -> expert"
        )
        for service in snapshot.services:
            suffix = f" [{service.badge}]" if service.badge else ""
            lines.append(f"{service.name}: {service.state}{suffix} - {service.detail}")
        for note in snapshot.notes:
            lines.append(f"note: {note}")
        return "\n".join(lines) + "\n"

    def _service_grid(self, services: Sequence[ServiceCard], *, width: int) -> str:
        columns = 2 if width >= 96 else 1
        card_width = (width - 3) // columns if columns == 2 else width
        rendered = [self._card(service, width=card_width).splitlines() for service in services]
        if columns == 1:
            return "\n".join(line for card in rendered for line in card)

        rows: list[str] = []
        for index in range(0, len(rendered), 2):
            left = rendered[index]
            right = rendered[index + 1] if index + 1 < len(rendered) else [" " * card_width] * len(left)
            height = max(len(left), len(right))
            left += [" " * card_width] * (height - len(left))
            right += [" " * card_width] * (height - len(right))
            rows.extend(f"{left[i]}   {right[i]}" for i in range(height))
        return "\n".join(rows)

    def _card(self, service: ServiceCard, *, width: int) -> str:
        inner = max(12, width - 4)
        color = _state_color(service.state)
        title = _fit(f"{service.name} {service.badge}".strip(), inner)
        state = _fit(f"{service.state}: {service.detail}", inner)
        return "\n".join(
            (
                f"+{'-' * (inner + 2)}+",
                f"| {BOLD}{title:<{inner}}{RESET} |",
                f"| {color}{state:<{inner}}{RESET} |",
                f"+{'-' * (inner + 2)}+",
            )
        )


class DashboardWatch(AbstractContextManager["DashboardWatch"]):
    """Alternate-screen dashboard updater for status/watch flows."""

    def __init__(
        self,
        *,
        stream: IO[str] = sys.stdout,
        enabled: bool = True,
    ) -> None:
        self.stream = stream
        self.enabled = enabled
        self._display = DashboardDisplay(stream=stream, enabled=enabled)

    def __enter__(self) -> "DashboardWatch":
        if self.enabled:
            self.stream.write(HIDE_CURSOR + CLEAR_SCREEN + HOME)
            self.stream.flush()
        return self

    def update(self, snapshot: DashboardSnapshot) -> None:
        if self.enabled:
            self.stream.write(HOME)
        self._display.print(snapshot)

    def __exit__(self, exc_type, exc, traceback) -> bool:
        if self.enabled:
            self.stream.write(SHOW_CURSOR)
            self.stream.flush()
        return False


@dataclass(frozen=True)
class PayoutRow:
    peer_id: str
    amount: str
    status: str


class PayoutsDisplay:
    """Future payments view placeholder.

    CLI_UI_TODO: replace this with real ledger/API-backed payout data once the
    protocol exposes a settled payment contract. This class must stay inert
    until then; do not render synthetic balances from routing state.
    """

    def render(self, rows: Sequence[PayoutRow]) -> str:
        raise NotImplementedError(
            "CLI_UI_TODO: payouts display needs a real ledger/API contract"
        )


@dataclass(frozen=True)
class RenderingOption:
    name: str
    fit: str
    verdict: str
    note: str


def terminal_rendering_options() -> tuple[RenderingOption, ...]:
    """Current 3D/layout assessment captured as code, not a vague TODO."""
    return (
        RenderingOption(
            name="ANSI scene renderer",
            fit="now",
            verdict="ship",
            note="Dependency-free, stable in tmux/screen/logs, good for a 2.5D network map.",
        ),
        RenderingOption(
            name="Rich/Textual",
            fit="next",
            verdict="prototype behind optional dependency",
            note="Best Python path for true widget/layout TUI once dependencies are acceptable.",
        ),
        RenderingOption(
            name="Yoga flex layout",
            fit="later",
            verdict="do not add directly yet",
            note="Useful as a layout algorithm, but it is not a terminal UI framework by itself.",
        ),
        RenderingOption(
            name="Ratatui",
            fit="release binary",
            verdict="consider for a Rust frontend",
            note="Strong full-screen TUI option if the release binary grows a Rust UI shell.",
        ),
        RenderingOption(
            name="WebGL/Three.js",
            fit="companion app",
            verdict="not for the terminal CLI",
            note="Right home for real 3D; keep terminal CLI readable and scriptable.",
        ),
    )


class TerminalSceneRenderer:
    """Terminal-safe pseudo-3D network renderer.

    This is intentionally a projection, not a graphics engine. CLI_UI_TODO:
    revisit real 3D only in a companion UI or optional TUI dependency path.
    """

    def render_network_scene(self, network: AskNetworkDisplay, *, width: int = 96) -> str:
        matcher = _fit(network.matcher_host, 28)
        relay = _fit(network.relay_id, 18)
        expert = "selected expert"
        prefix = " " * max(0, min(12, width // 10))
        return "\n".join(
            (
                f"{DIM}network map{RESET}",
                f"{prefix}        +------------------------------+",
                f"{prefix}       /| matcher {matcher:<20}|",
                f"{prefix}      / | value_x {network.value_x_prefix:<20}|",
                f"{prefix}     /  +------------------------------+",
                f"{prefix}+--------+        +--------------------+        +----------------+",
                f"{prefix}| you    |------->| relay {relay:<12}|------->| {expert:<14}|",
                f"{prefix}+--------+        | {network.relay_endpoint:<18}|        +----------------+",
                f"{prefix}                  +--------------------+",
                f"{prefix}mode={network.route_mode} peers={network.relay_count}",
            )
        )


ExperimentalSceneRenderer = TerminalSceneRenderer


class StatusRail(AbstractContextManager["StatusRail"]):
    """Single-line status rail that behaves well in tmux/screen/logging."""

    _frames = ("-", "\\", "|", "/")

    def __init__(
        self,
        label: str,
        *,
        stream: IO[str] = sys.stderr,
        interval: float = 0.12,
        enabled: bool = True,
    ) -> None:
        self.label = label
        self.stream = stream
        self.interval = interval
        self.enabled = enabled
        self._done = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = False

    @classmethod
    def disabled(cls) -> "StatusRail":
        return cls("", enabled=False)

    def start(self) -> None:
        if not self.enabled or self._started:
            return
        self._started = True
        self._thread = threading.Thread(target=self._run, name="tenet-status-rail", daemon=True)
        self._thread.start()

    def stop(self, final_label: str = "network exchange complete") -> None:
        if not self.enabled or not self._started:
            return
        self._done.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        self.stream.write(f"\r{CLEAR_LINE}{GREEN}ok{RESET}  {final_label}\n")
        self.stream.flush()

    def fail(self, final_label: str = "network exchange failed") -> None:
        if not self.enabled or not self._started:
            return
        self._done.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        self.stream.write(f"\r{CLEAR_LINE}{RED}error{RESET}  {final_label}\n")
        self.stream.flush()

    def __exit__(self, exc_type, exc, traceback) -> bool:
        if exc_type is None:
            self.stop()
        else:
            self.fail()
        return False

    def _run(self) -> None:
        index = 0
        while not self._done.is_set():
            frame = self._frames[index % len(self._frames)]
            self.stream.write(f"\r{CLEAR_LINE}{MAGENTA}{frame}{RESET}  {self.label}")
            self.stream.flush()
            index += 1
            self._done.wait(self.interval)


def _first_string(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)) and value:
        return str(value[0])
    return ""


def _fit(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    if width <= 1:
        return value[:width]
    return value[: width - 1] + "~"


def _state_color(state: str) -> str:
    normalized = state.lower()
    if normalized in {"ok", "ready", "trusted", "configured"}:
        return GREEN
    if normalized in {"unknown", "not checked", "pending"}:
        return YELLOW
    if normalized in {"failed", "error", "blocked"}:
        return RED
    return CYAN
