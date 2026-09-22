#!/usr/bin/env python3

# Copyright Antti Kultanen <antti.kultanen@molukki.com>
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

"""
Validates a log file produced by nflog_dns --json.

Every non-empty line in the file must parse as JSON.
Additional checks are selected with repeatable flags:

  --count k=v[,k=v...]:N   exactly N lines have all of the given
                           top-level key/value pairs
  --exists k=v[,k=v...]    at least one line has all of the given pairs
  --absent k=v[,k=v...]    no line has all of the given pairs

A value of <MISSING> matches a line where that key is not present.
"""

import argparse
import json
import sys


def coerce(value):
    if value == "<MISSING>":
        return _MISSING
    if value == "true":
        return True
    if value == "false":
        return False
    try:
        return int(value)
    except ValueError:
        return value


class _Missing:
    def __repr__(self):
        return "<MISSING>"


_MISSING = _Missing()


def parse_pairs(spec):
    pairs = {}
    for item in spec.split(","):
        key, _, value = item.partition("=")
        pairs[key] = coerce(value)
    return pairs


def matches(obj, pairs):
    for key, expected in pairs.items():
        if expected is _MISSING:
            if key in obj:
                return False
        elif obj.get(key, _MISSING) != expected:
            return False
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile")
    parser.add_argument("--count", action="append", default=[], metavar="k=v[,k=v...]:N")
    parser.add_argument("--exists", action="append", default=[], metavar="k=v[,k=v...]")
    parser.add_argument("--absent", action="append", default=[], metavar="k=v[,k=v...]")
    args = parser.parse_args()

    objects = []
    with open(args.logfile, "r") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                objects.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"{args.logfile}:{lineno}: not valid JSON: {e}\nline: {line}", file=sys.stderr)
                return 1

    failed = False

    for spec in args.count:
        pairs_spec, _, expected_str = spec.rpartition(":")
        pairs = parse_pairs(pairs_spec)
        expected = int(expected_str)
        actual = sum(1 for obj in objects if matches(obj, pairs))
        if actual != expected:
            print(f"--count {spec}: expected {expected}, found {actual} matching line(s)", file=sys.stderr)
            failed = True

    for spec in args.exists:
        pairs = parse_pairs(spec)
        if not any(matches(obj, pairs) for obj in objects):
            print(f"--exists {spec}: no line matched", file=sys.stderr)
            failed = True

    for spec in args.absent:
        pairs = parse_pairs(spec)
        if any(matches(obj, pairs) for obj in objects):
            print(f"--absent {spec}: a line matched but should not have", file=sys.stderr)
            failed = True

    if failed:
        return 1

    print(f"OK: {len(objects)} line(s), all valid JSON, all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
