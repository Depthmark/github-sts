#!/usr/bin/env python3
"""Enforce the mechanical rules in .agents/standards/WRITING_STANDARD.md.

Covered:
  - no em or en dash punctuation in prose (hyphens stay valid)
  - no unexplained hype words
  - no generic AI framing

Not covered, because they need a human: factual integrity, audience fit, and
whether a claim is supported by evidence.

Code fences, inline code spans, and table rows are excluded. An em dash used as
a "not applicable" marker inside a table cell is typography, not prose, and the
metrics and API reference tables use it that way deliberately.
"""

import os
import re
import sys

ROOT = os.path.join("docs", "content")

HYPE = [
    "powerful", "robust", "seamless", "seamlessly", "revolutionary",
    "game changing", "game-changing", "cutting edge", "cutting-edge",
    "effortless", "blazing fast", "best-in-class",
]

AI_PHRASES = [
    "in today's", "it is important to note", "at its core",
    "let's dive", "let's delve", "whether you're a", "isn't just about",
]

DASH = re.compile(r"[—–]")
INLINE_CODE = re.compile(r"`[^`\n]*`")


def prose_lines(path):
    """Yield (line number, text) for prose lines, with inline code removed."""
    in_fence = False
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            stripped = line.strip()
            if stripped.startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence or stripped.startswith("|"):
                continue
            yield number, INLINE_CODE.sub("", line)


def markdown_files(root):
    for directory, _, files in os.walk(root):
        for name in sorted(files):
            if name.endswith(".md"):
                yield os.path.join(directory, name)


def main():
    if not os.path.isdir(ROOT):
        print(f"run from the repository root: {ROOT} not found", file=sys.stderr)
        return 2

    violations = []
    checked = 0

    for path in sorted(markdown_files(ROOT)):
        checked += 1
        for number, text in prose_lines(path):
            if DASH.search(text):
                violations.append(f"{path}:{number}: em or en dash in prose")
            lowered = text.lower()
            for word in HYPE:
                if re.search(r"\b" + re.escape(word) + r"\b", lowered):
                    violations.append(
                        f"{path}:{number}: unexplained hype word '{word}'"
                    )
            for phrase in AI_PHRASES:
                if phrase in lowered:
                    violations.append(
                        f"{path}:{number}: generic AI phrasing '{phrase}'"
                    )

    if violations:
        print(f"writing standard: {len(violations)} violation(s)", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1

    print(f"writing standard: {checked} pages, clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
