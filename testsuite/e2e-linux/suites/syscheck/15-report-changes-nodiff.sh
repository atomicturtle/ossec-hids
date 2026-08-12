#!/usr/bin/env bash
# 15 — report_changes diff in alert; nodiff truncates content
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
FIXTURE="$E2E_ROOT/fixtures/syscheck/sample.txt"
failed=0

while read -r name; do
    [[ -z "$name" ]] && continue
    host_load "$INVENTORY" "$name"
    if host_requires_vm && [[ "$HOST_BACKEND" == "podman" ]]; then
        log "skip $name (requires: vm)"; continue
    fi
    log "=== 15-report-changes-nodiff: $name ==="
    if ! (
        transport_prepare
        transport_bash "
            set -e
            rm -rf /opt/e2e-syscheck
            mkdir -p /opt/e2e-syscheck
            rm -f $OSSEC_DIR/queue/syscheck/syscheck $OSSEC_DIR/queue/syscheck/.syscheck.cpt
        "
        transport_copy "$FIXTURE" /opt/e2e-syscheck/report.txt
        transport_copy "$FIXTURE" /opt/e2e-syscheck/secret.txt
        # watched.txt also required by helpers that may look for it — create baseline
        transport_bash "cp /opt/e2e-syscheck/report.txt /opt/e2e-syscheck/watched.txt"

        sk_apply_syscheck_xml "$(cat <<'EOF'
  <syscheck>
    <frequency>60</frequency>
    <scan_on_start>yes</scan_on_start>
    <auto_ignore>no</auto_ignore>
    <alert_new_files>yes</alert_new_files>
    <directories check_all="yes" realtime="yes" report_changes="yes">/opt/e2e-syscheck</directories>
    <nodiff>/opt/e2e-syscheck/secret.txt</nodiff>
  </syscheck>
EOF
)"
        pkg_restart_ossec
        sk_stamp_mark
        sk_wait_analysisd_stable
        sk_wait_prescan /opt/e2e-syscheck/report.txt
        sk_assert_db_has /opt/e2e-syscheck/secret.txt
        sk_wait_ending_scan 1
        sk_assert_no_socketerr_since_mark
        sk_truncate_alerts

        # report_changes: edit report.txt → expect diff hunks in alert
        transport_bash "
            printf '%s\n' 'line one CHANGED for report_changes' 'line two stays until edited' > /opt/e2e-syscheck/report.txt
        "
        sk_wait_alert 'report.txt' "alert for report.txt change"
        transport_bash "
            grep -E 'Rule: 550' -A80 $SK_ALERTS | grep -F 'report.txt' -A40 | grep -E '@@|^[-+]|What changed|CHANGED' | grep -E '.' >/dev/null
        " || die "report_changes alert missing diff evidence"

        # nodiff: edit secret.txt → truncated marker, no real content from fixture
        sk_truncate_alerts
        transport_bash "
            printf '%s\n' 'SECRET-VALUE-SHOULD-NOT-APPEAR' 'line two' > /opt/e2e-syscheck/secret.txt
        "
        sk_wait_alert 'secret.txt' "alert for secret.txt change"
        transport_bash "
            block=\$(grep -E 'Rule: 550' -A80 $SK_ALERTS | grep -F 'secret.txt' -A40)
            echo \"\$block\" | grep -F 'Diff truncated because nodiff option' >/dev/null
            ! echo \"\$block\" | grep -F 'SECRET-VALUE-SHOULD-NOT-APPEAR' >/dev/null
        " || die "nodiff did not truncate / leaked secret content"
        sk_assert_no_socketerr_since_mark
        log "OK: report_changes + nodiff"
    ); then
        failed=1
        [[ "$KEEP_GOING" == "1" ]] || die "15-report-changes-nodiff failed on $name"
        warn "continuing after failure on $name"
    fi
done < <(inventory_list_hosts "$INVENTORY" "$BACKEND_FILTER" server)

[[ "$failed" -eq 0 ]] || die "15-report-changes-nodiff had failures"
log "15-report-changes-nodiff: OK"
