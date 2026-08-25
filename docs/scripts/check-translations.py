#!/usr/bin/env python3
"""Fail when the French tree drifts from the English tree.

English is the source language; French is the required translation. This
checks, in order of severity:

  1. every English page has a French counterpart, and vice versa
  2. every page declares translationKey, so the language switcher pairs them
  3. heading counts match, which catches whole sections that were never
     translated
  4. the French word count is at least MIN_RATIO of the English, which catches
     sections that were dropped without removing a heading

Known drift is recorded in translation-baseline.json so the check can be
enforced on new work while existing debt is paid down. Entries are reported but
do not fail the run; anything not in the baseline does. When a baselined page is
repaired the check says so, so the baseline cannot rot.
"""

import json
import os
import re
import sys

ROOT = os.path.join("docs", "content")
EN = os.path.join(ROOT, "en")
FR = os.path.join(ROOT, "fr")
BASELINE = os.path.join("docs", "scripts", "translation-baseline.json")

# French runs roughly 10 to 20 percent longer than English, so a ratio below
# this means content is missing rather than merely concise.
MIN_RATIO = 0.75

# Language-neutral by design: snippets are shared across both trees.
SKIP_DIRS = {"shared"}


def pages(base):
    found = set()
    for directory, _, files in os.walk(base):
        top = os.path.relpath(directory, base).split(os.sep)[0]
        if top in SKIP_DIRS:
            continue
        for name in files:
            if name.endswith(".md"):
                found.add(os.path.relpath(os.path.join(directory, name), base))
    return found


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def front_matter(text):
    match = re.match(r"^---\n(.*?)\n---\n", text, flags=re.S)
    return match.group(1) if match else ""


def body(text):
    text = re.sub(r"^---\n.*?\n---\n", "", text, flags=re.S)
    return re.sub(r"```.*?```", "", text, flags=re.S)


def headings(text):
    return [line for line in body(text).splitlines() if re.match(r"^#{1,6} ", line)]


def word_count(text):
    return len(re.findall(r"\S+", body(text)))


def load_baseline():
    if not os.path.exists(BASELINE):
        return {}
    with open(BASELINE, encoding="utf-8") as handle:
        data = json.load(handle)
    return data.get("known_drift", {})


def main():
    if not os.path.isdir(EN) or not os.path.isdir(FR):
        print(f"run from the repository root: {ROOT} not found", file=sys.stderr)
        return 2

    baseline = load_baseline()
    errors = []
    accepted = []
    repaired = []

    en_pages = pages(EN)
    fr_pages = pages(FR)

    for rel in sorted(en_pages - fr_pages):
        errors.append(f"missing French translation: content/fr/{rel}")
    for rel in sorted(fr_pages - en_pages):
        errors.append(f"French page has no English source: content/fr/{rel}")

    for base, lang in ((EN, "en"), (FR, "fr")):
        for rel in sorted(pages(base)):
            if "translationKey" not in front_matter(read(os.path.join(base, rel))):
                errors.append(f"missing translationKey: content/{lang}/{rel}")

    for rel in sorted(en_pages & fr_pages):
        en_text = read(os.path.join(EN, rel))
        fr_text = read(os.path.join(FR, rel))
        allowed = baseline.get(rel, [])
        page_issues = []

        en_headings = len(headings(en_text))
        fr_headings = len(headings(fr_text))
        if en_headings != fr_headings:
            page_issues.append(
                ("headings", f"heading count differs: {rel} "
                             f"(en={en_headings}, fr={fr_headings})")
            )

        en_words = word_count(en_text)
        fr_words = word_count(fr_text)
        if en_words:
            ratio = fr_words / en_words
            if ratio < MIN_RATIO:
                page_issues.append(
                    ("ratio", f"French page is truncated: {rel} "
                              f"({fr_words}/{en_words} words = {ratio:.2f}, "
                              f"minimum {MIN_RATIO})")
                )

        seen = set()
        for kind, message in page_issues:
            seen.add(kind)
            (accepted if kind in allowed else errors).append(message)

        for kind in allowed:
            if kind not in seen:
                repaired.append(
                    f"{rel}: '{kind}' is fixed, remove it from {BASELINE}"
                )

    for rel in sorted(set(baseline) - (en_pages & fr_pages)):
        repaired.append(f"{rel}: no longer a page pair, remove it from {BASELINE}")

    for message in accepted:
        print(f"  known drift (baselined): {message}")
    for message in repaired:
        print(f"  baseline is stale: {message}")

    if errors:
        print(f"translation parity: {len(errors)} error(s)", file=sys.stderr)
        for message in errors:
            print(f"  {message}", file=sys.stderr)
        return 1

    summary = f"translation parity: {len(en_pages)} page pairs, no new drift"
    if accepted:
        summary += f" ({len(accepted)} known issue(s) still baselined)"
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
