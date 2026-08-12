#!/usr/bin/env bash
# 13 — realtime alert quickly vs scheduled-only after frequency window
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

# Count differential endings: "Ending syscheck scan." without "(forwarding"
_sk_diff_ending_count() {
    transport_bash "
        mark=\$(grep -n 'E2E_SYSCHECK_MARK' $SK_LOG | tail -1 | cut -d: -f1)
        [[ -n \"\$mark\" ]] || { echo 0; exit 0; }
        tail -n +\$mark $SK_LOG | grep -F 'Ending syscheck scan.' | grep -vcF '(forwarding' || true
    "
}

while read -r name; do
    [[ -z "$name" ]] && continue
    host_load "$INVENTORY" "$name"
    if host_requires_vm && [[ "$HOST_BACKEND" == "podman" ]]; then
        log "skip $name (requires: vm)"; continue
    fi
    log "=== 13-realtime-vs-scheduled: $name ==="
    if ! (
        transport_prepare
        transport_bash "
            rm -rf /opt/e2e-syscheck-rt /opt/e2e-syscheck-sched
            mkdir -p /opt/e2e-syscheck-rt /opt/e2e-syscheck-sched
            echo base-rt > /opt/e2e-syscheck-rt/watched.txt
            echo base-sched > /opt/e2e-syscheck-sched/watched.txt
            rm -f $OSSEC_DIR/queue/syscheck/syscheck $OSSEC_DIR/queue/syscheck/.syscheck.cpt
        "
        sk_apply_syscheck_xml "$(cat <<'EOF'
  <syscheck>
    <frequency>15</frequency>
    <scan_on_start>yes</scan_on_start>
    <auto_ignore>no</auto_ignore>
    <alert_new_files>no</alert_new_files>
    <directories check_all="yes" realtime="yes">/opt/e2e-syscheck-rt</directories>
    <directories check_all="yes">/opt/e2e-syscheck-sched</directories>
  </syscheck>
EOF
)"
        pkg_restart_ossec
        sk_stamp_mark
        sk_wait_analysisd_stable
        sk_wait_prescan /opt/e2e-syscheck-rt/watched.txt
        sk_assert_db_has /opt/e2e-syscheck-sched/watched.txt
        sk_wait_ending_scan 1
        sk_assert_no_socketerr_since_mark
        sk_truncate_alerts

        # Confirm sched dir is NOT realtime (startup lines may precede mark).
        transport_bash "
            line=\$(grep -F \"Monitoring directory: '/opt/e2e-syscheck-sched'\" $SK_LOG | tail -1)
            [[ -n \"\$line\" ]] || exit 1
            echo \"\$line\" | grep -F realtime >/dev/null && exit 1
            rt=\$(grep -F \"Directory set for real time monitoring: '/opt/e2e-syscheck-sched'\" $SK_LOG | tail -1 || true)
            [[ -z \"\$rt\" ]] || exit 1
            grep -F \"Monitoring directory: '/opt/e2e-syscheck-rt'\" $SK_LOG | tail -1 | grep -F realtime >/dev/null
        " || die "sched directory unexpectedly has realtime or is not monitored"
        log "OK: sched dir monitored without realtime"

        # Realtime: expect alert within 25s
        transport_bash "echo rt-change-\$(date +%s) > /opt/e2e-syscheck-rt/watched.txt"
        _start=$(date +%s)
        _ok=0
        while true; do
            if transport_bash "grep -E 'Rule: 550' -A8 $SK_ALERTS | grep -F 'e2e-syscheck-rt/watched.txt' >/dev/null"; then
                _ok=1
                break
            fi
            _now=$(date +%s)
            if (( _now - _start >= 25 )); then
                break
            fi
            sleep 1
        done
        [[ "$_ok" -eq 1 ]] || die "realtime change did not produce rule 550 within 25s"
        log "OK: realtime → 550 within 25s"

        # Scheduled: change after baseline; no early alert; then 550 within
        # frequency+slack with realtime quiet (adaptive select timeout honors
        # <frequency> instead of blocking for SYSCHECK_WAIT).
        before_diff=$(_sk_diff_ending_count)
        before_diff=${before_diff:-0}
        transport_bash "echo sched-change-\$(date +%s) > /opt/e2e-syscheck-sched/watched.txt"
        sleep 8
        if transport_bash "grep -E 'Rule: 550' -A8 $SK_ALERTS | grep -F 'e2e-syscheck-sched/watched.txt' >/dev/null"; then
            die "scheduled-only path alerted too early (expected no realtime)"
        fi
        log "OK: scheduled path had no early alert (diff endings before=$before_diff)"

        _start=$(date +%s)
        _ok=0
        while true; do
            if transport_bash "grep -E 'Rule: 550' -A8 $SK_ALERTS | grep -F 'e2e-syscheck-sched/watched.txt' >/dev/null"; then
                _ok=1
                break
            fi
            transport_bash "pgrep -x ossec-analysisd >/dev/null" || die "analysisd died during scheduled wait"
            _now=$(date +%s)
            # frequency=15 plus scan overhead / slack
            if (( _now - _start >= 60 )); then
                after_diff=$(_sk_diff_ending_count)
                die "scheduled path did not produce rule 550 within 60s (diff endings before=$before_diff after=${after_diff:-?})"
            fi
            sleep 3
        done
        [[ "$_ok" -eq 1 ]] || die "scheduled path did not produce rule 550"
        log "OK: scheduled path → 550 after scan (no RT nudge)"
    ); then
        failed=1
        [[ "$KEEP_GOING" == "1" ]] || die "13-realtime-vs-scheduled failed on $name"
        warn "continuing after failure on $name"
    fi
done < <(inventory_list_hosts "$INVENTORY" "$BACKEND_FILTER" server)

[[ "$failed" -eq 0 ]] || die "13-realtime-vs-scheduled had failures"
log "13-realtime-vs-scheduled: OK"
