"""A deliberately small lexical scanner.

`unbla` never tries to be a JS parser. It only needs one thing: the exact
character span of each *top-level* statement, so a decoy statement can be cut
out without touching anything else. Cutting is validated afterwards by asking a
real engine to parse the result (``node --check``), so the scanner is allowed to
be simple — but it must be correct about strings, templates and comments, or it
will slice through a literal.

Note: characters that usually appear as escapes are spelled with ``chr()`` on
purpose, so this file carries no backslash literals and survives any
double-escaping layer between author and repository.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

BACKSLASH = chr(92)
NEWLINE = chr(10)
WS = " " + chr(9) + chr(13) + NEWLINE
QUOTES = "'" + chr(34)

# Word characters are spelled as explicit classes: [$ _ A-Z a-z 0-9]
WORD0 = "[$_A-Za-z]"
WORD = "[$_A-Za-z0-9]"

DECLARATION = re.compile(
    "^(?:export[ ]+)?(?:default[ ]+)?(?:async[ ]+)?"
    "(?:(?P<kind>function|class|const|let|var)[ ]+)?"
    "(?P<name>" + WORD0 + WORD + "*)"
)

BLOCK_FIRST = ("function", "class", "async function", "if", "for", "while",
               "switch", "try", "do")


@dataclass(frozen=True)
class Statement:
    start: int
    end: int
    text: str
    name: str | None
    kind: str | None


def _skip_string(src: str, i: int, quote: str) -> int:
    """Return the index just past a quoted literal starting at ``i``."""
    i += 1
    n = len(src)
    while i < n:
        c = src[i]
        if c == BACKSLASH:
            i += 2
            continue
        if c == quote:
            return i + 1
        if c == NEWLINE and quote != "`":
            return i  # unterminated: bail out at the newline
        i += 1
    return n


def _skip_template(src: str, i: int) -> int:
    """Return the index just past a template literal starting at ``i``."""
    i += 1
    n = len(src)
    depth = 0
    while i < n:
        c = src[i]
        if c == BACKSLASH:
            i += 2
            continue
        if depth == 0 and c == "`":
            return i + 1
        if c == "$" and src[i:i + 2] == "${":
            depth += 1
            i += 2
            continue
        if depth and c == "}":
            depth -= 1
        i += 1
    return n


def scan_top_level(src: str) -> list[Statement]:
    """Split a script into top-level statements, preserving their spans."""
    statements: list[Statement] = []
    n = len(src)
    i = 0
    start: int | None = None
    depth = 0

    def flush(end: int) -> None:
        nonlocal start
        if start is None:
            return
        text = src[start:end]
        if text.strip():
            head = text.lstrip()
            match = DECLARATION.match(head)
            statements.append(Statement(
                start, end, text,
                match.group("name") if match else None,
                match.group("kind") if match else None,
            ))
        start = None

    while i < n:
        c = src[i]
        if c in WS:
            i += 1
            continue
        if c == "/" and i + 1 < n:
            nxt = src[i + 1]
            if nxt == "/":
                end = src.find(NEWLINE, i)
                i = n if end < 0 else end
                continue
            if nxt == "*":
                end = src.find("*/", i + 2)
                i = n if end < 0 else end + 2
                continue
        if start is None:
            # a statement begins at the first meaningful character
            start = i
        if c in QUOTES:
            i = _skip_string(src, i, c)
            continue
        if c == "`":
            i = _skip_template(src, i)
            continue
        if c in "([{":
            depth += 1
            i += 1
            continue
        if c in ")]}":
            depth = max(0, depth - 1)
            i += 1
            if depth == 0 and c == "}":
                head = src[start:i].lstrip()
                if head.startswith(BLOCK_FIRST) or re.match("(const|let|var)[ ]", head):
                    # block-bodied statement: may be followed by a semicolon
                    j = i
                    while j < n and src[j] in WS:
                        j += 1
                    if j < n and src[j] == ";":
                        i = j + 1
                    flush(i)
            continue
        if c == ";" and depth == 0:
            i += 1
            flush(i)
            continue
        i += 1

    flush(n)
    return statements


def identifier_uses(src: str, name: str) -> int:
    """Count whole-word uses of ``name`` outside strings and comments."""
    if not name:
        return 0
    count = 0
    n = len(src)
    i = 0
    word_re = re.compile(WORD0 + WORD + "*")
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] in "/*":
            if src[i + 1] == "/":
                end = src.find(NEWLINE, i)
                i = n if end < 0 else end
            else:
                end = src.find("*/", i + 2)
                i = n if end < 0 else end + 2
            continue
        if c in QUOTES:
            i = _skip_string(src, i, c)
            continue
        if c == "`":
            i = _skip_template(src, i)
            continue
        if (c.isalpha() or c in "_$"):
            match = word_re.match(src, i)
            word = match.group(0) if match else ""
            if word == name:
                count += 1
            i += len(word) or 1
            continue
        i += 1
    return count
