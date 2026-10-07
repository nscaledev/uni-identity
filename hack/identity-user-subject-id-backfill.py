#!/usr/bin/env python3

"""Backfill Identity User subject-ID labels without changing User specs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid


NAMESPACE = uuid.UUID("b11bc9c8-5ac7-4554-9911-99725c71e24c")
RESOURCE = "users.identity.unikorn-cloud.org"
LABEL = "unikorn-cloud.org/user-subject-id"


def identifier(subject: str) -> str:
    value = uuid.UUID(bytes=hashlib.sha1(NAMESPACE.bytes + subject.encode()).digest()[:16], version=5)
    while not value.hex[0].isalpha():
        value = uuid.UUID(bytes=hashlib.sha1(NAMESPACE.bytes + value.bytes).digest()[:16], version=5)
    return str(value)


def kubectl(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["kubectl", *args], check=False, capture_output=True, text=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write missing labels")
    args = parser.parse_args()
    if not os.environ.get("KUBECONFIG"):
        print("error: KUBECONFIG must be set", file=sys.stderr)
        return 1
    if shutil.which("kubectl") is None:
        print("error: kubectl is not installed", file=sys.stderr)
        return 1
    result = kubectl("get", RESOURCE, "--all-namespaces", "--output=json")
    if result.returncode:
        print(result.stderr.strip(), file=sys.stderr)
        return 1
    users = json.loads(result.stdout).get("items", [])
    missing = applied = 0
    for user in users:
        metadata, spec = user.get("metadata", {}), user.get("spec", {})
        subject, current = spec.get("subject"), metadata.get("labels", {}).get(LABEL)
        if not subject:
            print(f"error: {metadata.get('namespace')}/{metadata.get('name')} has no subject", file=sys.stderr)
            return 1
        wanted = identifier(subject)
        if current == wanted:
            continue
        if current:
            print(f"error: {metadata['namespace']}/{metadata['name']} has conflicting {LABEL}", file=sys.stderr)
            return 1
        missing += 1
        if args.apply:
            write = kubectl("label", RESOURCE, "--namespace", metadata["namespace"], metadata["name"], f"{LABEL}={wanted}")
            if write.returncode:
                print(write.stderr.strip(), file=sys.stderr)
                return 1
            applied += 1
    print(f"missing={missing}")
    print(f"applied={applied}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
