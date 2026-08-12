#!/usr/bin/env bash
# 14 — ignore / restrict / no_recurse → DB presence/absence
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
    log "=== 14-ignore-restrict-norecurse: $name ==="
    if ! (
        transport_prepare
        transport_bash "
            set -e
            rm -rf /opt/e2e-syscheck
            mkdir -p /opt/e2e-syscheck/subdir /opt/e2e-syscheck/ignored
            echo keep > /opt/e2e-syscheck/keep.conf
            echo skip > /opt/e2e-syscheck/skip.log
            echo deep > /opt/e2e-syscheck/subdir/deep.conf
            echo ign > /opt/e2e-syscheck/ignored/secret.conf
            rm -f $OSSEC_DIR/queue/syscheck/syscheck $OSSEC_DIR/queue/syscheck/.syscheck.cpt
        "
        sk_apply_syscheck_xml "$(cat <<'EOF'
  <syscheck>
    <frequency>86400</frequency>
    <scan_on_start>yes</scan_on_start>
    <auto_ignore>no</auto_ignore>
    <alert_new_files>no</alert_new_files>
    <directories check_all="yes" restrict=".conf$" no_recurse="yes">/opt/e2e-syscheck</directories>
    <ignore>/opt/e2e-syscheck/ignored</ignore>
  </syscheck>
EOF
)"
        pkg_restart_ossec
        sk_stamp_mark
        sk_wait_analysisd_stable
        sleep 1

        # Wait for Finished + DB file
        _start=$(date +%s)
        while true; do
            if transport_bash "
                mark=\$(grep -n 'E2E_SYSCHECK_MARK' $SK_LOG | tail -1 | cut -d: -f1)
                tail -n +\$mark $SK_LOG | grep -F 'Finished creating syscheck database' >/dev/null
                [[ -f $SK_DB ]]
            "; then
                break
            fi
            _now=$(date +%s)
            if (( _now - _start >= E2E_TIMEOUT )); then
                die "prescan did not finish for filter suite"
            fi
            sleep 2
        done

        sk_assert_db_has /opt/e2e-syscheck/keep.conf
        sk_assert_db_lacks /opt/e2e-syscheck/skip.log
        sk_assert_db_lacks /opt/e2e-syscheck/subdir/deep.conf
        sk_assert_db_lacks /opt/e2e-syscheck/ignored/secret.conf
        log "OK: ignore/restrict/no_recurse DB filters"
    ); then
        failed=1
        [[ "$KEEP_GOING" == "1" ]] || die "14-ignore-restrict-norecurse failed on $name"
        warn "continuing after failure on $name"
    fi
done < <(inventory_list_hosts "$INVENTORY" "$BACKEND_FILTER" server)

[[ "$failed" -eq 0 ]] || die "14-ignore-restrict-norecurse had failures"
log "14-ignore-restrict-norecurse: OK"
