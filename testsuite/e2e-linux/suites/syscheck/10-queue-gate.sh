#!/usr/bin/env bash
# 10 — queue health gate: no socketerr + content change → rule 550
set -euo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_ROOT="$(cd "$SUITE_DIR/../.." && pwd)"
# shellcheck source=/dev/null
source "$E2E_ROOT/lib/common.sh"
# shellcheck source=/dev/null
source "$E2E_ROOT/lib/inventory.sh"
# shellcheck source=/dev/null
source "$E2E_ROOT/lib/ssh.sh"
# shellcheck source=/dev/null
source "$E2E_ROOT/lib/podman_target.sh"
# shellcheck source=/dev/null
source "$E2E_ROOT/lib/transport.sh"
# shellcheck source=/dev/null
source "$E2E_ROOT/lib/pkg.sh"
# shellcheck source=/dev/null
source "$E2E_ROOT/lib/assert.sh"
# shellcheck source=/dev/null
source "$E2E_ROOT/lib/syscheck.sh"

INVENTORY="${1:?inventory required}"
BACKEND_FILTER="${E2E_BACKEND:-}"
KEEP_GOING="${E2E_KEEP_GOING:-0}"
failed=0

while read -r name; do
    [[ -z "$name" ]] && continue
    host_load "$INVENTORY" "$name"
    if host_requires_vm && [[ "$HOST_BACKEND" == "podman" ]]; then
        log "skip $name (requires: vm)"
        continue
    fi
    log "=== 10-queue-gate: $name ==="
    if ! (
        transport_prepare
        transport_bash "[[ -x $OSSEC_DIR/bin/ossec-syscheckd ]]"
        sk_queue_gate /opt/e2e-syscheck
    ); then
        failed=1
        [[ "$KEEP_GOING" == "1" ]] || die "10-queue-gate failed on $name"
        warn "continuing after failure on $name"
    fi
done < <(inventory_list_hosts "$INVENTORY" "$BACKEND_FILTER" server)

[[ "$failed" -eq 0 ]] || die "10-queue-gate had failures"
log "10-queue-gate: OK"
