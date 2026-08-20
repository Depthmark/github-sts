#!/usr/bin/env python3
"""Resolve every internal link and fragment in the built site.

Hugo's relref validates the target page but not the anchor, so a translated
page can point at an English heading slug, build without a warning, and drop
the reader at the top of the page. This runs against docs/public so it sees
exactly what a reader's browser would resolve.

Usage:
    python3 docs/scripts/check-links.py --base docs/public --base-path /github-sts
"""

import argparse
import html
import os
import re
import sys
from urllib.parse import unquote, urlparse

SKIP_SCHEMES = ("http://", "https://", "mailto:", "javascript:", "data:", "tel:")

HREF = re.compile(r'<a[^>]+href=("[^"]*"|\'[^\']*\'|[^\s>]+)')
ID = re.compile(r'\sid=("[^"]*"|\'[^\']*\'|[^\s>]+)')


def load(base):
    documents = {}
    for directory, _, files in os.walk(base):
        for name in files:
            if name.endswith(".html"):
                path = os.path.join(directory, name)
                with open(path, encoding="utf-8", errors="replace") as handle:
                    documents[path] = handle.read()
    return documents


def url_of(path, base):
    rel = "/" + os.path.relpath(path, base).replace(os.sep, "/")
    if rel.endswith("index.html"):
        rel = rel[: -len("index.html")]
    return rel


def attr(raw):
    return html.unescape(raw.strip("\"'"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="docs/public",
                        help="directory holding the built site")
    parser.add_argument("--base-path", default="",
                        help="path prefix baked in by baseURL, e.g. /github-sts")
    args = parser.parse_args()

    if not os.path.isdir(args.base):
        print(f"build the site first: {args.base} not found", file=sys.stderr)
        return 2

    documents = load(args.base)
    known = set()
    anchors = {}
    for path, text in documents.items():
        url = url_of(path, args.base)
        known.add(url)
        anchors[url] = {unquote(attr(raw)) for raw in ID.findall(text)}

    broken = set()
    bad_anchor = set()

    for path, text in documents.items():
        source = url_of(path, args.base)
        for match in HREF.finditer(text):
            href = attr(match.group(1))
            if not href or href.startswith(SKIP_SCHEMES) or href.startswith("#"):
                continue

            parsed = urlparse(href)
            target = unquote(parsed.path)
            if not target:
                continue

            if args.base_path and target.startswith(args.base_path + "/"):
                target = target[len(args.base_path):]
            elif not target.startswith("/"):
                here = source if source.endswith("/") else source.rsplit("/", 1)[0] + "/"
                target = os.path.normpath(here + target)

            leaf = target.rsplit("/", 1)[-1]
            if not target.endswith("/") and "." not in leaf:
                target += "/"

            on_disk = os.path.exists(os.path.join(args.base, target.lstrip("/")))
            if target not in known and not on_disk:
                broken.add((source, href))
            elif parsed.fragment and target in anchors:
                # Goldmark percent-encodes non-ASCII in hrefs while the id
                # attribute keeps the literal character, so "#r%c3%a9ponses"
                # and id="réponses" are the same anchor to a browser. Compare
                # decoded on both sides.
                if unquote(parsed.fragment) not in anchors[target]:
                    bad_anchor.add((source, href))

    for source, href in sorted(broken):
        print(f"  broken link:   {source} -> {href}", file=sys.stderr)
    for source, href in sorted(bad_anchor):
        print(f"  broken anchor: {source} -> {href}", file=sys.stderr)

    if broken or bad_anchor:
        print(f"link check: {len(broken)} broken link(s), "
              f"{len(bad_anchor)} broken anchor(s)", file=sys.stderr)
        return 1

    print(f"link check: {len(documents)} pages, "
          f"all internal links and anchors resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
