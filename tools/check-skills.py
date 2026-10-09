#!/usr/bin/env python3
"""Check the agent skills in skills/ against the trust-policy schema.

Skills ship with the app and describe its policy format, so a schema change
that a skill does not follow is a release defect. This fails when:

  - a skill directory has no SKILL.md, or its front matter lacks a valid
    `name` (lowercase letters, digits and hyphens, equal to the directory
    name, 64 characters at most) or `description` (1 to 1024 characters);
  - a policy example names a field, a permission or a permission level that
    internal/policy/yaml/schema_v1.json does not define. A policy example is a
    *.sts.yaml file, or a fenced yaml block with a top-level `issuer:` key;
  - prose names a dotted field under `github.` or `permissions.` in an inline
    code span that the schema does not define.

Not covered: a field named in prose without that dotted form, and whether an
example satisfies the schema's required-field rules. For the second, --extract
writes each policy example to a directory and `make check-skills` runs
check-jsonschema over it.

Standard library only, so it runs before any toolchain is installed.
"""

import argparse
import json
import os
import re
import sys

NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
FENCE = re.compile(r"^\s*```")
KEY = re.compile(r"^(\s*)(-\s+)?([A-Za-z_][A-Za-z0-9_-]*):(\s+(.*))?$")
DOTTED = re.compile(r"`((?:github|permissions)\.[A-Za-z0-9_.\[\]-]+)`")


def front_matter(lines):
    """Return the front matter as a dict of single-line scalars, or None."""
    if not lines or lines[0].strip() != "---":
        return None
    fields = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return fields
        match = re.match(r"^([A-Za-z_-]+):\s*(.*)$", line)
        if match:
            fields[match.group(1)] = match.group(2).strip().strip("'\"")
    return None


def check_front_matter(path, directory, errors):
    with open(path, encoding="utf-8") as handle:
        fields = front_matter(handle.read().splitlines())
    if fields is None:
        errors.append(f"{path}: no front matter between two '---' lines")
        return
    name = fields.get("name", "")
    if not NAME.match(name) or len(name) > 64:
        errors.append(f"{path}: name {name!r} is missing or not lowercase letters, digits and hyphens")
    elif name != directory:
        errors.append(f"{path}: name {name!r} differs from its directory {directory!r}")
    description = fields.get("description", "")
    if not 1 <= len(description) <= 1024:
        errors.append(f"{path}: description must be one line of 1 to 1024 characters, got {len(description)}")


def yaml_blocks(path):
    """Yield (first line number, lines) for each fenced yaml block."""
    block, start, language = None, 0, ""
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if FENCE.match(line):
                if block is None:
                    language = line.strip().lstrip("`").strip().lower()
                    block, start = [], number + 1
                else:
                    if language in ("yaml", "yml"):
                        yield start, block
                    block = None
            elif block is not None:
                block.append(line.rstrip("\n"))


def key_paths(lines, first):
    """Yield (line number, path, value) for each mapping key, by indentation."""
    stack = []
    for offset, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = KEY.match(line)
        if not match:
            continue
        indent = len(match.group(1)) + len(match.group(2) or "")
        while stack and stack[-1][0] >= indent:
            stack.pop()
        stack.append((indent, match.group(3)))
        value = (match.group(5) or "").split(" #")[0].strip().strip("'\"")
        yield first + offset, [key for _, key in stack], value


def resolve(schema, node):
    while "$ref" in node:
        target = schema
        for part in node["$ref"].lstrip("#/").split("/"):
            target = target[part]
        node = target
    return node


def check_path(schema, path, value):
    """Return why a key path is not in the schema, or None when it is."""
    node = schema
    for depth, key in enumerate(path):
        node = resolve(schema, node)
        if node.get("type") == "array":
            node = resolve(schema, node["items"])
        properties = node.get("properties", {})
        if key in properties:
            node = properties[key]
        elif node.get("additionalProperties") not in (None, False):
            return None
        else:
            return f"field {'.'.join(path[:depth + 1])!r} is absent from the schema"
    node = resolve(schema, node)
    if value and "enum" in node and value not in node["enum"]:
        return f"{'.'.join(path)}: {value!r} is not one of {node['enum']}"
    return None


def check_policy(schema, path, first, lines, errors, extract):
    if extract:
        name = re.sub(r"[^A-Za-z0-9]+", "-", f"{path}-{first}").strip("-") + ".sts.yaml"
        with open(os.path.join(extract, name), "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    for number, keys, value in key_paths(lines, first):
        problem = check_path(schema, keys, value)
        if problem:
            errors.append(f"{path}:{number}: {problem}")


def check_prose(schema, path, errors):
    in_fence = False
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if FENCE.match(line):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for reference in DOTTED.findall(line):
                keys = [part for part in reference.replace("[]", "").split(".") if part]
                problem = check_path(schema, keys, "")
                if problem:
                    errors.append(f"{path}:{number}: {problem}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--skills", default="skills")
    parser.add_argument("--schema", default=os.path.join("internal", "policy", "yaml", "schema_v1.json"))
    parser.add_argument("--extract", help="directory to write each policy example to")
    args = parser.parse_args()
    if args.extract:
        os.makedirs(args.extract, exist_ok=True)

    with open(args.schema, encoding="utf-8") as handle:
        schema = json.load(handle)

    errors = []
    skills = sorted(
        entry for entry in os.listdir(args.skills)
        if os.path.isdir(os.path.join(args.skills, entry))
    )
    if not skills:
        errors.append(f"{args.skills}: no skill directory found")

    for skill in skills:
        root = os.path.join(args.skills, skill)
        manifest = os.path.join(root, "SKILL.md")
        if not os.path.isfile(manifest):
            errors.append(f"{root}: no SKILL.md")
            continue
        check_front_matter(manifest, skill, errors)
        for directory, _, files in os.walk(root):
            for name in sorted(files):
                path = os.path.join(directory, name)
                if name.endswith(".md"):
                    for first, lines in yaml_blocks(path):
                        if any(line.startswith("issuer:") for line in lines):
                            check_policy(schema, path, first, lines, errors, args.extract)
                    check_prose(schema, path, errors)
                elif name.endswith(".sts.yaml"):
                    with open(path, encoding="utf-8") as handle:
                        check_policy(schema, path, 1, handle.read().splitlines(), errors, args.extract)

    for error in errors:
        print(error)
    if errors:
        print(f"\n{len(errors)} problem(s) in {args.skills}/")
        return 1
    print(f"{len(skills)} skill(s) checked against {args.schema}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
