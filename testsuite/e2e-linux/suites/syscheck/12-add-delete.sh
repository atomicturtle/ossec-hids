#!/usr/bin/env bash
# 12 — file add → 554 (alert_new_files) and delete → 553
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
        log "skip $name (requires: vm)"; continue
    fi
    log "=== 12-add-delete: $name ==="
    if ! (
        transport_prepare
        sk_isolate_tree /opt/e2e-syscheck
        sk_wait_prescan /opt/e2e-syscheck/watched.txt
        sk_wait_ending_scan 1
        sk_assert_no_socketerr_since_mark
        sk_truncate_alerts

        NEWF="newfile-$(date +%s).txt"
        transport_bash "echo brand-new > /opt/e2e-syscheck/$NEWF"
        _start=$(date +%s)
        _ok=0
        while true; do
            if transport_bash "grep -E 'Rule: 554' -A8 $SK_ALERTS | grep -F \"$NEWF\" >/dev/null"; then
                _ok=1
                break
            fi
            _now=$(date +%s)
            if (( _now - _start >= E2E_TIMEOUT )); then
                break
            fi
            sleep 2
        done
        [[ "$_ok" -eq 1 ]] || die "rule 554 for $NEWF not observed"
        log "OK: rule 554 file added ($NEWF)"

        transport_bash "rm -f /opt/e2e-syscheck/watched.txt"
        _start=$(date +%s)
        _ok=0
        while true; do
            if transport_bash "grep -E 'Rule: 553' -A8 $SK_ALERTS | grep -F 'watched.txt' >/dev/null"; then
                _ok=1
                break
            fi
            _now=$(date +%s)
            if (( _now - _start >= E2E_TIMEOUT )); then
                break
            fi
            sleep 2
        done
        [[ "$_ok" -eq 1 ]] || die "rule 553 for watched.txt not observed"
        sk_assert_no_socketerr_since_mark
        log "OK: add→554 delete→553"
    ); then
        failed=1
        [[ "$KEEP_GOING" == "1" ]] || die "12-add-delete failed on $name"
        warn "continuing after failure on $name"
    fi
done < <(inventory_list_hosts "$INVENTORY" "$BACKEND_FILTER" server)

[[ "$failed" -eq 0 ]] || die "12-add-delete had failures"
log "12-add-delete: OK"
