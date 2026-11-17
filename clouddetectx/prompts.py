"""Arrow-key prompt helpers shared by the interactive screens."""

from __future__ import annotations

from typing import Any, Callable

import questionary
from questionary import Choice, Separator, Style

STYLE = Style([
    ("qmark", "fg:#00afff bold"),
    ("question", "bold"),
    ("pointer", "fg:#00afff bold"),
    ("highlighted", "fg:#00afff bold"),
    ("selected", "fg:#5fd75f"),
    ("answer", "fg:#5fd75f bold"),
    ("instruction", "fg:#808080 italic"),
    ("separator", "fg:#6c6c6c"),
    ("disabled", "fg:#6c6c6c italic"),
])

# questionary returns a Choice's *title* when its value is None, so "go back" entries use a sentinel.
BACK = "__back__"

__all__ = ["BACK", "Choice", "Separator", "STYLE", "checkbox", "confirm", "password", "select", "text"]


def select(message: str, choices: list, **kw) -> Any:
    """Returns the chosen value, or None for Back/Cancel/Ctrl+C."""
    answer = questionary.select(message, choices=choices, style=STYLE, qmark=">", pointer=">",
                                instruction="(arrow keys, Enter)", **kw).ask()
    return None if answer == BACK else answer


def confirm(message: str, default: bool = False) -> bool:
    return bool(questionary.confirm(message, default=default, style=STYLE, qmark=">").ask())


def text(message: str, default: str = "", validate: Callable[[str], bool | str] | None = None,
         instruction: str | None = None) -> str | None:
    return questionary.text(message, default=default, validate=validate, style=STYLE, qmark=">",
                            instruction=instruction).ask()


def password(message: str, validate: Callable[[str], bool | str] | None = None) -> str | None:
    return questionary.password(message, validate=validate, style=STYLE, qmark=">").ask()


def checkbox(message: str, choices: list, validate: Callable[[list], bool | str] | None = None) -> list | None:
    kwargs = {"validate": validate} if validate else {}
    return questionary.checkbox(message, choices=choices, style=STYLE, qmark=">",
                                instruction="(space to toggle, Enter to confirm)", **kwargs).ask()
