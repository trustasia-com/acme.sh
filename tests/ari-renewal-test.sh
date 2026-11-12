#!/usr/bin/env sh

# Offline regression tests for renewal scheduling. The real renew() function is
# used; only ACME network access and final certificate issuance are replaced.

# shellcheck shell=sh
# Functions and variables below are called indirectly by the sourced acme.sh.
# shellcheck disable=SC2034,SC2329

TEST_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH='' cd -- "$TEST_DIR/.." && pwd)
ACME_SH="$PROJECT_ROOT/acme.sh"
TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/acme-ari-renewal.XXXXXX") || exit 1
_cleanup() {
  if [ "${KEEP_TEST_TMP:-}" ]; then
    printf 'test files: %s\n' "$TEST_TMP"
  else
    rm -rf "$TEST_TMP"
  fi
}
trap '_cleanup' EXIT HUP INT TERM

DOMAIN="short-lived.example"
NOW=1794373200     # 2026-11-11T05:00:00Z
NOT_BEFORE=1793876399 # 2026-11-05T10:59:59Z
NOT_AFTER=1794481199  # 2026-11-12T10:59:59Z
STALE_NEXT=1796385485 # 2026-12-04T11:58:05Z
VALID_TO_SAFE_NEXT=1794394799 # one day before NOT_AFTER for relative --valid-to
FALLBACK_NEXT=1794279599      # NOT_AFTER minus one third of the seven-day lifetime

_passed=0
_failed=0

_pass() {
  _passed=$((_passed + 1))
  printf 'ok %s - %s\n' "$((_passed + _failed))" "$1"
}

_fail() {
  _failed=$((_failed + 1))
  printf 'not ok %s - %s\n' "$((_passed + _failed))" "$1" >&2
  printf '  %s\n' "$2" >&2
}

_assert_equals() {
  if [ "$2" = "$3" ]; then
    _pass "$1"
  else
    _fail "$1" "expected '$2', got '$3'"
  fi
}

_assert_contains() {
  if printf '%s\n' "$3" | grep -F "$2" >/dev/null 2>&1; then
    _pass "$1"
  else
    _fail "$1" "output did not contain '$2'"
  fi
}

_assert_not_contains() {
  if printf '%s\n' "$3" | grep -F "$2" >/dev/null 2>&1; then
    _fail "$1" "output unexpectedly contained '$2'"
  else
    _pass "$1"
  fi
}

_assert_before_expiry() {
  if [ -n "$2" ] && [ "$2" -lt "$NOT_AFTER" ]; then
    _pass "$1"
  else
    _fail "$1" "renewal time '$2' was not before notAfter '$NOT_AFTER'"
  fi
}

_write_conf() {
  _wc_next=$1
  _wc_extra=${2:-}
  cat >"$TEST_TMP/home/$DOMAIN/$DOMAIN.conf" <<EOF
Le_Domain='$DOMAIN'
Le_API='https://ca.invalid/directory'
Le_CertCreateTime='1793879885'
Le_CertCreateTimeStr='2026-11-05T11:58:05Z'
Le_NextRenewTime='$_wc_next'
Le_NextRenewTimeStr='stale test value'
Le_Keylength='2048'
Le_Webroot='no'
$_wc_extra
EOF
}

_run_renew() {
  _rr_next=$1
  _rr_ari_response=$2
  _rr_valid_to=${3:-}
  _rr_now=${5:-$NOW}
  _rr_cert=${6:-$TEST_TMP/cert.pem}
  _rr_conf_extra=${7:-}
  _rr_case_dir="$TEST_TMP/case-$((_passed + _failed + 1))-$4"
  mkdir -p "$_rr_case_dir"
  cp "$_rr_cert" "$TEST_TMP/home/$DOMAIN/$DOMAIN.cer"
  cp "$TEST_TMP/key.pem" "$TEST_TMP/home/$DOMAIN/$DOMAIN.key"
  _write_conf "$_rr_next" "$_rr_conf_extra"
  : >"$_rr_case_dir/issue.called"

  (
    LE_CONFIG_HOME="$TEST_TMP/home"
    CERT_HOME="$TEST_TMP/home"
    export LE_CONFIG_HOME CERT_HOME
    set --
    # shellcheck source=/dev/null
    . "$ACME_SH" >/dev/null 2>&1

    _time() {
      printf '%s\n' "$TEST_NOW"
    }
    _initAPI() {
      ACME_RENEWAL_INFO="https://ca.invalid/renewalInfo"
      return 0
    }
    _get_ARI() {
      printf '%s\n' "$TEST_ARI_RESPONSE"
    }
    _ensure_install() {
      return 0
    }
    _ensure_deploy() {
      return 0
    }
    _send_notify() {
      return 0
    }
    issue() {
      printf 'called\n' >"$TEST_ISSUE_MARKER"
      return 0
    }

    TEST_ARI_RESPONSE="$_rr_ari_response"
    TEST_ISSUE_MARKER="$_rr_case_dir/issue.called"
    TEST_NOW="$_rr_now"
    Le_Valid_To="$_rr_valid_to"
    renew "$DOMAIN" >"$_rr_case_dir/output.log" 2>&1
    printf '%s' "$?" >"$_rr_case_dir/status"
  )

  TEST_CASE_DIR="$_rr_case_dir"
}

_make_cert() {
  openssl ca -config "$TEST_TMP/openssl.cnf" -batch -notext -selfsign \
    -in "$TEST_TMP/csr.pem" -keyfile "$TEST_TMP/key.pem" \
    -startdate "$2" -enddate "$3" -out "$1" >/dev/null 2>&1 || return 1
}

openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$TEST_TMP/key.pem" -out "$TEST_TMP/csr.pem" \
  -subj "/CN=$DOMAIN" >/dev/null 2>&1 || {
  printf 'could not create test key and CSR\n' >&2
  exit 1
}
: >"$TEST_TMP/index.txt"
printf '01\n' >"$TEST_TMP/serial"
cat >"$TEST_TMP/openssl.cnf" <<EOF
[ca]
default_ca = CA_default
[CA_default]
database = $TEST_TMP/index.txt
serial = $TEST_TMP/serial
new_certs_dir = $TEST_TMP
default_md = sha256
policy = policy_any
unique_subject = no
[policy_any]
commonName = supplied
EOF
_make_cert "$TEST_TMP/cert.pem" 20261105105959Z 20261112105959Z || {
  printf 'could not create test certificate\n' >&2
  exit 1
}
_make_cert "$TEST_TMP/long-cert.pem" 20261105105959Z 20270203105959Z || {
  printf 'could not create long-lived test certificate\n' >&2
  exit 1
}
mkdir -p "$TEST_TMP/home/$DOMAIN"

# A seven-day certificate with the production shape: ARI has no usable window
# and the cached default schedule is one month after issuance, past notAfter.
_run_renew "$STALE_NEXT" "" "" "short-cert-ari-unavailable"
_assert_equals "short certificate inside the one-third fallback window renews" "0" "$(cat "$TEST_CASE_DIR/status")"
_assert_equals "short certificate inside the fallback window reaches issuance" "called" "$(cat "$TEST_CASE_DIR/issue.called")"
_assert_contains "unsafe cached schedule emits a warning" "WARNING" "$(cat "$TEST_CASE_DIR/output.log")"
_saved_next=$(sed -n "s/^Le_NextRenewTime='\\([^']*\\)'.*/\\1/p" "$TEST_TMP/home/$DOMAIN/$DOMAIN.conf")
_assert_before_expiry "repaired cache is earlier than notAfter" "$_saved_next"
_assert_equals "seven-day certificate uses notAfter minus one third of its lifetime" "$FALLBACK_NEXT" "$_saved_next"

# A cache written by the previous one-day fallback is safe but now too late.
# When ARI is unavailable it must move to the new two-thirds-of-life window.
_run_renew "$VALID_TO_SAFE_NEXT" "" "" "previous-safe-cache"
_assert_equals "previous safe cache enters the new fallback window" "0" "$(cat "$TEST_CASE_DIR/status")"
_assert_equals "previous safe cache reaches issuance under the new policy" "called" "$(cat "$TEST_CASE_DIR/issue.called")"
_assert_equals "previous safe cache is moved to the one-third fallback" "$FALLBACK_NEXT" "$(sed -n "s/^Le_NextRenewTime='\\([^']*\\)'.*/\\1/p" "$TEST_TMP/home/$DOMAIN/$DOMAIN.conf")"

# A future, valid ARI window retains the existing skip behavior.
_run_renew "$VALID_TO_SAFE_NEXT" '{"suggestedWindow":{"start":"2026-11-11T08:00:00Z","end":"2026-11-11T09:00:00Z"}}' "" "valid-future-ari"
_assert_equals "valid future ARI overrides the earlier local fallback without issuing" "2" "$(cat "$TEST_CASE_DIR/status")"
_assert_equals "valid future ARI window does not issue" "" "$(cat "$TEST_CASE_DIR/issue.called")"
_assert_equals "valid future ARI keeps deterministic window selection" "1794384000" "$(sed -n "s/^Le_NextRenewTime='\\([^']*\\)'.*/\\1/p" "$TEST_TMP/home/$DOMAIN/$DOMAIN.conf")"

# An ARI window whose selected point has passed still renews immediately.
_run_renew "$FALLBACK_NEXT" '{"suggestedWindow":{"start":"2026-11-11T00:00:00Z","end":"2026-11-11T01:00:00Z"}}' "" "valid-past-ari"
_assert_equals "valid elapsed ARI window renews immediately" "0" "$(cat "$TEST_CASE_DIR/status")"
_assert_equals "valid elapsed ARI window reaches issuance" "called" "$(cat "$TEST_CASE_DIR/issue.called")"

# Near expiry, the corrected two-thirds-of-lifetime schedule is already due.
_run_renew "$STALE_NEXT" "" "" "near-expiry" "$((NOT_AFTER - 3600))"
_assert_equals "near-expiry certificate renews instead of skipping" "0" "$(cat "$TEST_CASE_DIR/status")"
_assert_equals "near-expiry certificate reaches issuance" "called" "$(cat "$TEST_CASE_DIR/issue.called")"

# The safe window opens exactly at the repaired timestamp, not one cron later.
_run_renew "$STALE_NEXT" "" "" "safe-window-boundary" "$FALLBACK_NEXT"
_assert_equals "renewal starts at the exact safe-window boundary" "0" "$(cat "$TEST_CASE_DIR/status")"
_assert_equals "safe-window boundary reaches issuance" "called" "$(cat "$TEST_CASE_DIR/issue.called")"

# One second before that boundary it must wait, with the repaired cache saved.
_run_renew "$STALE_NEXT" "" "" "before-safe-window" "$((FALLBACK_NEXT - 1))"
_assert_equals "renewal waits one second before the fallback boundary" "2" "$(cat "$TEST_CASE_DIR/status")"
_assert_equals "pre-boundary check does not issue" "" "$(cat "$TEST_CASE_DIR/issue.called")"
_assert_equals "pre-boundary check persists the one-third fallback" "$FALLBACK_NEXT" "$(sed -n "s/^Le_NextRenewTime='\\([^']*\\)'.*/\\1/p" "$TEST_TMP/home/$DOMAIN/$DOMAIN.conf")"

# Invalid ARI dates have the same safe fallback as an unavailable endpoint.
_run_renew "$STALE_NEXT" '{"suggestedWindow":{"start":"invalid","end":""}}' "" "invalid-ari" "$((NOT_AFTER - 3600))"
_assert_equals "invalid ARI response does not block a due renewal" "0" "$(cat "$TEST_CASE_DIR/status")"
_assert_equals "invalid ARI response reaches issuance" "called" "$(cat "$TEST_CASE_DIR/issue.called")"

# A normal 90-day certificate with a safe cached time is left untouched.
_run_renew "$STALE_NEXT" "" "" "long-lived" "$NOW" "$TEST_TMP/long-cert.pem"
_assert_equals "long-lived certificate keeps its normal skip behavior" "2" "$(cat "$TEST_CASE_DIR/status")"
_assert_not_contains "long-lived certificate needs no cache warning" "WARNING" "$(cat "$TEST_CASE_DIR/output.log")"
_assert_equals "long-lived certificate cache remains unchanged" "$STALE_NEXT" "$(sed -n "s/^Le_NextRenewTime='\\([^']*\\)'.*/\\1/p" "$TEST_TMP/home/$DOMAIN/$DOMAIN.conf")"

# Fixed-date --valid-to is non-renewable and must not be repaired or renewed.
_run_renew "$STALE_NEXT" "" "2026-11-12T10:59:59Z" "fixed-valid-to"
_assert_equals "fixed valid-to retains non-renewable skip behavior" "2" "$(cat "$TEST_CASE_DIR/status")"
_assert_not_contains "fixed valid-to is excluded from cache repair" "WARNING" "$(cat "$TEST_CASE_DIR/output.log")"
_assert_equals "fixed valid-to cache remains unchanged" "$STALE_NEXT" "$(sed -n "s/^Le_NextRenewTime='\\([^']*\\)'.*/\\1/p" "$TEST_TMP/home/$DOMAIN/$DOMAIN.conf")"

# Relative --valid-to retains expiry-based scheduling during cache repair.
_run_renew "$STALE_NEXT" "" "+7d" "relative-valid-to"
_assert_equals "relative valid-to waits for its safe renewal time" "2" "$(cat "$TEST_CASE_DIR/status")"
_assert_equals "relative valid-to repairs against notAfter" "$VALID_TO_SAFE_NEXT" "$(sed -n "s/^Le_NextRenewTime='\\([^']*\\)'.*/\\1/p" "$TEST_TMP/home/$DOMAIN/$DOMAIN.conf")"

# The certificate's notBefore, not the later local creation timestamp, is the
# lifecycle anchor for an explicit two-day renewal schedule.
_run_renew "$STALE_NEXT" "" "" "actual-not-before" "$NOW" "$TEST_TMP/cert.pem" "Le_RenewalDays='2'"
_assert_equals "certificate notBefore anchors the fallback schedule" "1793962799" "$(sed -n "s/^Le_NextRenewTime='\\([^']*\\)'.*/\\1/p" "$TEST_TMP/home/$DOMAIN/$DOMAIN.conf")"
_assert_equals "due certificate using actual notBefore reaches issuance" "called" "$(cat "$TEST_CASE_DIR/issue.called")"

# MTC landmark initialization follows the same safe renewal decision path.
_run_renew "$STALE_NEXT" "" "" "mtc-landmark" "$((NOT_AFTER - 3600))" "$TEST_TMP/cert.pem" "Le_MTC_Landmark='1'"
_assert_equals "MTC landmark configuration renews near expiry" "0" "$(cat "$TEST_CASE_DIR/status")"
_assert_equals "MTC landmark configuration reaches issuance" "called" "$(cat "$TEST_CASE_DIR/issue.called")"

# Direct calculation checks pin the cap independently of the renewal fixtures.
_assert_equals "30-day certificate caps at twenty days" "1001728000" "$("$ACME_SH" _calc_next_renew_time 1000000000 30 1002592000)"
_assert_equals "47-day certificate keeps the earlier 30-day schedule" "1002505600" "$("$ACME_SH" _calc_next_renew_time 1000000000 30 1004060800)"
_assert_equals "90-day certificate keeps the earlier 60-day schedule" "1005097600" "$("$ACME_SH" _calc_next_renew_time 1000000000 60 1007776000)"
_assert_equals "six-hour certificate renews two hours before expiry" "1000014400" "$("$ACME_SH" _calc_next_renew_time 1000000000 30 1000021600)"
_assert_equals "one-second lifetime keeps the cap before expiry" "1000000000" "$("$ACME_SH" _calc_next_renew_time 1000000000 30 1000000001)"
_assert_equals "missing notAfter preserves the original fixed schedule" "1005097600" "$("$ACME_SH" _calc_next_renew_time 1000000000 60 "")"

printf '# %s passed, %s failed\n' "$_passed" "$_failed"
[ "$_failed" -eq 0 ]
