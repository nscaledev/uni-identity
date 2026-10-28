#!/usr/bin/env bash
# Validate the provider version a pact_verification dispatch asks to verify, and print it.
#
#   provider-version.sh <sha>
#
# Pact verifies a changed pact against the provider's main and against every deployed provider
# version (https://docs.pact.io/pact_broker/webhooks#the-contract-requiring-verification-published-event),
# so a dispatch may name the deployed commit in client_payload.provider_version. The payload is
# untrusted input: it must be a full lowercase commit SHA that is already on origin/main, because
# deployed releases are main commits. Anything else, such as a branch, a tag, a short SHA or a commit
# off main, is refused. Run it in a checkout of main with full history.
set -euo pipefail

requested="${1:-}"
if ! [[ "$requested" =~ ^[0-9a-f]{40}$ ]]; then
  echo "provider_version '$requested' is not a full commit SHA" >&2
  exit 1
fi
if ! git merge-base --is-ancestor "$requested" origin/main 2> /dev/null; then
  echo "provider_version $requested is not a commit on origin/main" >&2
  exit 1
fi
echo "$requested"
