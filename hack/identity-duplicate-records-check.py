#!/usr/bin/env python3

"""Report identity records that a rollout could have duplicated.

Users are grouped by folded subject, OrganizationUsers by organization and
user, and Quotas by organization. Any group with more than one record is
printed, and the exit status is 1. Nothing is changed.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
from collections import defaultdict

ORGANIZATION_LABEL = "unikorn-cloud.org/organization"
USER_LABEL = "unikorn-cloud.org/user"
GROUP = "identity.unikorn-cloud.org"


def load_normalize():
    """Share the subject folding with the backfill script, so there is one implementation."""
    path = pathlib.Path(__file__).with_name("identity-user-subject-id-backfill.py")
    spec = importlib.util.spec_from_file_location("backfill", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.normalize


def record_name(item: dict) -> str:
    metadata = item.get("metadata", {})
    return f"{metadata.get('namespace')}/{metadata.get('name')}"


def labels(item: dict) -> dict:
    return item.get("metadata", {}).get("labels") or {}


def grouped_duplicates(items: list[dict], key) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = defaultdict(list)
    for item in items:
        group = key(item)
        if group:
            groups[group].append(record_name(item))
    return {group: sorted(names) for group, names in groups.items() if len(names) > 1}


def find_duplicates(users: list[dict], organization_users: list[dict], quotas: list[dict], normalize) -> dict[str, dict[str, list[str]]]:
    def organization_user_key(item: dict) -> str:
        organization, user = labels(item).get(ORGANIZATION_LABEL), labels(item).get(USER_LABEL)
        return f"{organization}/{user}" if organization and user else ""

    return {
        "users": grouped_duplicates(users, lambda item: normalize(item.get("spec", {}).get("subject", ""))),
        "organizationusers": grouped_duplicates(organization_users, organization_user_key),
        "quotas": grouped_duplicates(quotas, lambda item: labels(item).get(ORGANIZATION_LABEL, "")),
    }


def kubectl_items(resource: str) -> list[dict]:
    result = subprocess.run(["kubectl", "get", f"{resource}.{GROUP}", "--all-namespaces", "--output=json"], check=False, capture_output=True, text=True)
    if result.returncode:
        print(result.stderr.strip(), file=sys.stderr)
        raise SystemExit(1)
    return json.loads(result.stdout).get("items", [])


def main() -> int:
    if not os.environ.get("KUBECONFIG"):
        print("error: KUBECONFIG must be set", file=sys.stderr)
        return 1
    if shutil.which("kubectl") is None:
        print("error: kubectl is not installed", file=sys.stderr)
        return 1
    duplicates = find_duplicates(kubectl_items("users"), kubectl_items("organizationusers"), kubectl_items("quotas"), load_normalize())
    found = 0
    for kind, groups in duplicates.items():
        for group, names in sorted(groups.items()):
            found += 1
            print(f"{kind} {group}: {', '.join(names)}")
    print(f"duplicate groups={found}")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
