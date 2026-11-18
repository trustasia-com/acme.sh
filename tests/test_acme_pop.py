"""draft-ietf-acme-pop-01 regressions. Run with Python 3 and OpenSSL 3.5+."""

import base64
from email.utils import formatdate
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
OPENSSL = os.environ.get("ACME_OPENSSL_BIN", "openssl")


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


class PopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.order = self.work / "order.json"
        self.order.write_bytes(b'{"identifiers":[{"type":"dns","value":"example.com"}]}')

    def openssl(self, *args):
        return subprocess.run([OPENSSL, *map(str, args)], check=True, capture_output=True).stdout

    def shell(self, script, *args, check=True):
        env = dict(os.environ, ACME_OPENSSL_BIN=OPENSSL)
        result = subprocess.run(
            ["sh", "-c", 'set -- : "$@"; . "$2" >/dev/null; shift 2; ' + script, ":", str(ROOT / "acme.sh"), *map(str, args)],
            capture_output=True, text=True, env=env,
        )
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def kem_fixture(self, algorithm):
        key = self.work / "key.pem"
        public = self.work / "public.pem"
        ciphertext = self.work / "ciphertext"
        secret = self.work / "secret"
        self.openssl("genpkey", "-algorithm", algorithm, "-out", key)
        self.openssl("pkey", "-in", key, "-pubout", "-out", public)
        self.openssl("pkeyutl", "-encap", "-pubin", "-inkey", public, "-out", ciphertext, "-secret", secret)
        return key, ciphertext.read_bytes(), secret.read_bytes()

    def test_kem_key_generation_and_spki(self):
        for bits in (512, 768, 1024):
            with self.subTest(bits=bits):
                key = self.work / f"{bits}.pem"
                result = self.shell('_createkey "$1" "$2" && _pop_key_spki "$2"', f"ml-kem-{bits}", key)
                expected = self.openssl("pkey", "-in", key, "-pubout", "-outform", "DER")
                self.assertEqual(result.stdout.strip(), b64url(expected))
                self.assertEqual(key.stat().st_mode & 0o777, 0o600)

    def test_public_key_input_uses_canonical_spki(self):
        key = self.work / "key.pem"
        public = self.work / "public.pem"
        self.openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key)
        self.openssl("pkey", "-in", key, "-pubout", "-out", public)
        result = self.shell('_pop_public_key_spki "$1"', public)
        expected = self.openssl("pkey", "-in", key, "-pubout", "-outform", "DER")
        self.assertEqual(result.stdout.strip(), b64url(expected))

    def test_csr_input_extracts_public_key_and_algorithm(self):
        key = self.work / "key.pem"
        csr = self.work / "request.csr"
        public = self.work / "public.der"
        self.openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key)
        self.openssl("req", "-new", "-key", key, "-subj", "/CN=example.com", "-addext", "subjectAltName=DNS:example.com", "-out", csr)
        result = self.shell('_pop_csr="${1}"; _pop_write_public_key csr "$2" && _pop_key_length "$2"', csr, public)
        self.assertEqual(result.stdout.strip(), "ec-256")
        expected = self.openssl("pkey", "-in", key, "-pubout", "-outform", "DER")
        self.assertEqual(b64url(public.read_bytes()), b64url(expected))

    def test_csr_input_uses_csr_domains(self):
        key = self.work / "key.pem"
        csr = self.work / "request.csr"
        self.openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key)
        self.openssl("req", "-new", "-key", key, "-subj", "/CN=example.com", "-addext", "subjectAltName=DNS:example.com,DNS:www.example.com", "-out", csr)
        result = self.shell(
            '_csr="$1"; _main_domain=wrong.example; _alt_domains=wrong.example; Le_ACME_Pop=1; _pop_private_key="$2"; _pop_prepare_inputs; printf "%s|%s" "$_main_domain" "$_alt_domains"',
            csr, key,
        )
        self.assertEqual(result.stdout.strip(), "example.com|www.example.com")

    def test_external_proof_command_receives_challenge_files(self):
        domain = self.work / "domain"
        domain.mkdir()
        challenge = '{"type":"pop-01","popNonce":"nonce"}'
        command = domain / "proof-command"
        command.write_text(
            '#!/bin/sh\n'
            '[ -s "$ACME_POP_CHALLENGE_FILE" ] || exit 1\n'
            '[ -s "$ACME_POP_ORDER_FILE" ] || exit 1\n'
            'printf external-proof\n'
        )
        command.chmod(0o700)
        result = self.shell(
            'DOMAIN_PATH="$1"; Le_PopProofCommand="$2"; _pop_challenge_proof "" "$3" "$4"',
            domain, command, challenge, self.order,
        )
        self.assertEqual(result.stdout.strip(), "external-proof")
        self.assertEqual((domain / "pop-challenge.json").read_text(), challenge)

    def test_provider_requires_key_ref(self):
        result = self.shell(
            'Le_ACME_Pop=1; _pop_provider=pop_test; _main_domain=example.com; _pop_prepare_inputs',
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires --pop-key-ref", result.stderr)

        result = self.shell(
            'Le_ACME_Pop=1; _pop_key_ref=orphan; _main_domain=example.com; _pop_prepare_inputs',
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires --pop-provider", result.stderr)

    def test_csr_input_requires_a_proof_source(self):
        key = self.work / "key.pem"
        csr = self.work / "request.csr"
        self.openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key)
        self.openssl("req", "-new", "-key", key, "-subj", "/CN=example.com", "-addext", "subjectAltName=DNS:example.com", "-out", csr)
        result = self.shell(
            '_csr="$1"; Le_ACME_Pop=1; _pop_prepare_inputs', csr, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires a private key", result.stderr)

        result = self.shell(
            '_csr="$1"; _pop_private_key="$2"; Le_ACME_Pop=1; _pop_prepare_inputs; printf "%s" "$_key_length"',
            csr, key,
        )
        self.assertEqual(result.stdout.strip(), "ec-256")

    def test_pop_provider_receives_base64url_operations(self):
        key, ciphertext, _ = self.kem_fixture("ML-KEM-768")
        sig_key = self.work / "signature-key.pem"
        sig_public_der = self.work / "signature-public.der"
        self.openssl("genpkey", "-algorithm", "ED25519", "-out", sig_key)
        self.openssl("pkey", "-in", sig_key, "-pubout", "-outform", "DER", "-out", sig_public_der)
        public_der = self.work / "public.der"
        self.openssl("pkey", "-in", key, "-pubout", "-outform", "DER", "-out", public_der)
        provider = self.work / "pop_test.sh"
        provider.write_text(r'''
pop_test_get_public_key() {
    openssl pkey -in "$TEST_KEY" -pubout -outform DER | _base64 "" | _url_replace
}
pop_test_sign() {
    _durl_replace_base64 "$3" | _dbase64 >"$TEST_TMP/message"
    openssl pkeyutl -sign -rawin -inkey "$TEST_KEY" -in "$TEST_TMP/message" |
        _base64 "" | _url_replace
}
pop_test_decap() {
    _durl_replace_base64 "$3" | _dbase64 >"$TEST_TMP/ciphertext"
    openssl pkeyutl -decap -inkey "$TEST_KEY" -in "$TEST_TMP/ciphertext" -secret "$TEST_TMP/secret"
    _base64 "" <"$TEST_TMP/secret" | _url_replace
}
''')
        nonce = b64url(bytes(range(32)))
        expected_sig = self.shell('_pop_proof "$1" "$2" "$3"', sig_key, nonce, self.order).stdout.strip()
        script = r'''
TEST_KEY="$1"; TEST_TMP="$2"; TEST_PROVIDER="$3"; TEST_PUBLIC="$4"
export TEST_KEY TEST_TMP
DOMAIN_PATH="$2"; _pop_provider=pop_test; _pop_key_ref=test-key
_pop_public_key_der_path="$TEST_PUBLIC"
_findHook() { printf '%s' "$TEST_PROVIDER"; }
_pop_provider_proof pop_test "$5" "$6"
'''
        public_check = self.shell(
            'TEST_KEY="$1"; TEST_PROVIDER="$2"; _pop_provider=pop_test; _pop_key_ref=test-key; '
            '_findHook() { printf "%s" "$TEST_PROVIDER"; }; '
            '_pop_provider_get_public_key_der >"$3" && _pop_key_length "$3"',
            sig_key, provider, self.work / "provider-public.der",
        )
        self.assertEqual(public_check.stdout.strip(), "ed25519")
        actual_sig = self.shell(script, sig_key, self.work, provider, sig_public_der, nonce, self.order).stdout.strip()
        self.assertEqual(actual_sig, expected_sig)

        expected_kem = self.shell('_pop_kem_proof "$1" "$2" "$3"', key, b64url(ciphertext), self.order).stdout.strip()
        actual_kem = self.shell(
            script.replace('_pop_provider_proof pop_test "$5" "$6"', '_pop_provider_kem_proof pop_test "$5" "$6"'),
            key, self.work, provider, public_der, b64url(ciphertext), self.order,
        ).stdout.strip()
        self.assertEqual(actual_kem, expected_kem)

    def test_kem_proof_matches_independent_server(self):
        for bits in (512, 768, 1024):
            with self.subTest(bits=bits):
                key, ciphertext, secret = self.kem_fixture(f"ML-KEM-{bits}")
                prk = hmac.digest(bytes(32), secret, "sha256")
                mac_key = hmac.digest(prk, b"ACME-pop-01-KEM v1\x01", "sha256")
                expected = b64url(hmac.digest(mac_key, hashlib.sha256(self.order.read_bytes()).digest(), "sha256"))
                result = self.shell('_pop_kem_proof "$1" "$2" "$3"', key, b64url(ciphertext), self.order)
                self.assertEqual(result.stdout.strip(), expected)
                self.order.write_bytes(self.order.read_bytes() + b" ")
                changed = self.shell('_pop_kem_proof "$1" "$2" "$3"', key, b64url(ciphertext), self.order)
                self.assertNotEqual(changed.stdout.strip(), expected)

    def test_reject_malformed_ciphertexts(self):
        key, ciphertext, _ = self.kem_fixture("ML-KEM-768")
        encoded = b64url(ciphertext)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        noncanonical = encoded[:-1] + alphabet[alphabet.index(encoded[-1]) + 1]
        for value in ("", "!", encoded + "=", encoded + "\n", b64url(ciphertext[:-1]), b64url(ciphertext + b"x"), noncanonical):
            with self.subTest(value=value[:20]):
                result = self.shell('_pop_kem_proof "$1" "$2" "$3"', key, value, self.order, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_kem_never_falls_back_to_csr(self):
        key, _, _ = self.kem_fixture("ML-KEM-768")
        for length in ("ml-kem-768", "ec-256"):
            result = self.shell('CERT_KEY_PATH="$1"; issue() { echo UNEXPECTED_CSR; }; _pop_fallback_issue dns_ali example.com "" "$2"', key, length, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("UNEXPECTED_CSR", result.stdout)

    def test_kem_requires_pop_before_network(self):
        result = self.shell('DOMAIN_PATH="$1"; DOMAIN_CONF="$1/domain.conf"; _initpath() { :; }; _initAPI() { echo UNEXPECTED_NETWORK; }; issue dns_ali example.com "" ml-kem-768', self.work, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("require --acme-pop", result.stderr)
        self.assertNotIn("UNEXPECTED_NETWORK", result.stdout)

    def test_kem_capability_check_precedes_pre_hook(self):
        wrapper = self.work / "unsupported-openssl"
        wrapper.write_text('#!/bin/sh\nexit 1\n')
        wrapper.chmod(0o700)
        script = '''
DOMAIN_PATH="$1"; DOMAIN_CONF="$1/domain.conf"; CERT_KEY_PATH="$1/key"
ACME_OPENSSL_BIN="$2"; Le_ACME_Pop=1
_initpath() { :; }
_initAPI() { ACME_POP_SUPPORTED=1; }
_on_before_issue() { echo UNEXPECTED_PRE_HOOK; return 1; }
issue dns_ali example.com "" ml-kem-768
'''
        result = self.shell(script, self.work, wrapper, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("UNEXPECTED_PRE_HOOK", result.stdout)
        self.assertIn("OpenSSL", result.stderr)

    def test_kem_capability_check_uses_real_crypto(self):
        for bits in (512, 768, 1024):
            with self.subTest(bits=bits):
                result = self.shell('_pop_check_kem_support "$1"', f"ml-kem-{bits}")
                self.assertEqual(result.stdout, "")

    def test_explicit_signature_key_replacement_allows_csr_fallback(self):
        key, _, _ = self.kem_fixture("ML-KEM-768")
        (self.work / "domain.conf").write_text("Le_Keylength='ml-kem-768'\n")
        script = '''
DOMAIN_PATH="$1"; DOMAIN_CONF="$1/domain.conf"; CERT_KEY_PATH="$2"
_initpath() { :; }
FORCE=1
issue() {
  createDomainKey example.com "$4" >/dev/null || return 1
  _createcsr example.com "" "$CERT_KEY_PATH" "$DOMAIN_PATH/request.csr" "$DOMAIN_PATH/request.conf"
}
_pop_fallback_issue dns_ali example.com "" ec-256
'''
        self.shell(script, self.work, key)
        self.openssl("req", "-in", self.work / "request.csr", "-verify", "-noout")
        public = self.openssl("pkey", "-in", key, "-pubout", "-text_pub", "-noout")
        self.assertIn(b"prime256v1", public)

    def test_existing_kem_still_blocks_fallback_without_key_replacement(self):
        key, _, _ = self.kem_fixture("ML-KEM-768")
        for saved, force, renewing, before_done in (
            ("ml-kem-768", "", "", ""),
            ("ml-kem-768", "1", "1", ""),
            ("ec-256", "1", "", ""),
            ("ml-kem-768", "1", "", "1"),
        ):
            with self.subTest(saved=saved, force=force, renewing=renewing, before_done=before_done):
                (self.work / "domain.conf").write_text(f"Le_Keylength='{saved}'\n")
                result = self.shell('''
DOMAIN_CONF="$1/domain.conf"; CERT_KEY_PATH="$2"; FORCE="$3"
_ACME_IS_RENEW="$4"; _pop_before_issue_done="$5"
_clearup() { :; }; _on_issue_err() { :; }
issue() { echo UNEXPECTED_CSR; }
_pop_fallback_issue dns_ali example.com "" ec-256
''', self.work, key, force, renewing, before_done, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("UNEXPECTED_CSR", result.stdout)

    def test_pop_authorization_requires_exactly_one_challenge(self):
        challenge = {"type": "pop-01", "key": "synthetic-key", "status": "valid"}
        for challenges in ([challenge], [challenge, {}], [{}, challenge], [challenge, challenge]):
            auth = json.dumps({"status": "valid", "challenges": challenges}, separators=(",", ":"))
            for value in (auth, auth.replace("[", "[ \t\n").replace("]", " \t\n]")):
                with self.subTest(challenges=len(challenges), value=value):
                    result = self.shell('Le_PopKey=synthetic-key; response="$(printf "%s" "$1" | _normalizeJson)"; _pop_complete_authorization https://ca.example/auth', value, check=False)
                    self.assertEqual(result.returncode == 0, len(challenges) == 1)

    def test_authorization_uses_outer_status(self):
        challenge = {"type": "pop-01", "key": "synthetic-key", "status": "valid"}
        for status in ("expired", "deactivated", "revoked", "invalid", None):
            for outer_first in (False, True):
                auth = {"challenges": [challenge], "metadata": {"status": "valid"}}
                if status is not None:
                    auth = dict(status=status, **auth) if outer_first else dict(auth, status=status)
                result = self.shell('''
Le_PopKey=synthetic-key; response="$1"
_send_signed_request() { echo UNEXPECTED_NETWORK; return 1; }
_pop_complete_authorization https://ca.example/auth
''', json.dumps(auth, separators=(",", ":")), check=False)
                self.assertNotEqual(result.returncode, 0, (status, outer_first))
                self.assertEqual(result.stdout, "")

    def test_pop_polling_honors_retry_after_and_outer_status(self):
        script = '''
Le_PopKey=synthetic-key; Le_LinkOrder=https://ca.example/order
response='{"status":"pending","challenges":[{"type":"pop-01","key":"synthetic-key","status":"pending","url":"https://ca.example/challenge"}]}'
_pop_check_order_binding() { :; }
_pop_challenge_proof() { echo test-proof; }
_sleep() { echo "sleep:$1"; }
polls=0
_send_signed_request() {
  code=200
  responseHeaders='Retry-After: 120'
  case "$1" in
  */challenge)
    if [ -n "$2" ]; then response='{"status":"processing"}'; else response='{"status":"valid"}'; fi ;;
  *)
    polls=$((polls + 1))
    if [ "$polls" = 1 ]; then
      response='{"challenges":[{"status":"valid"}],"status":"pending","popKey":"synthetic-key"}'
    else
      response='{"challenges":[{"status":"invalid"}],"status":"valid","popKey":"synthetic-key"}'
    fi ;;
  esac
}
if [ "$1" = order ]; then _pop_wait_ready; else _pop_complete_authorization https://ca.example/auth; fi
'''
        for mode, expected in (("order", ["sleep:120"]), ("authorization", ["sleep:120", "sleep:120"])):
            with self.subTest(mode=mode):
                result = self.shell(script, mode)
                self.assertEqual(result.stdout.splitlines(), expected)

    def test_pop_polling_remains_bounded(self):
        result = self.shell('''
Le_PopKey=synthetic-key
_pop_check_order_binding() { :; }
_send_signed_request() { code=200; response='{"status":"pending","popKey":"synthetic-key"}'; responseHeaders=''; echo poll; }
_sleep() { echo "sleep:$1"; }
_pop_wait_ready
''', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.splitlines().count("poll"), 30)
        self.assertIn("Timed out", result.stderr)

    def test_pop_json_preserves_strings_and_ignores_nested_status(self):
        value = {
            "metadata": {"status": "invalid", "text": 'literal \\" [ } and spaces'},
            "challenges": [{"status": "expired"}],
            "text": 'a \\ "quote" [ ] { } 中文',
            "status": "valid",
        }
        encoded = json.dumps(value, indent="\t", ensure_ascii=False)
        compact = self.shell('printf "%s" "$1" | _pop_json', encoded).stdout
        self.assertEqual(json.loads(compact), value)
        self.assertEqual(self.shell('printf "%s" "$1" | _pop_status', encoded).stdout.strip(), "valid")
        for malformed in ('{"status":"valid"', '{"status":"valid", "unfinished":"', '{"status":"valid"}}'):
            self.assertEqual(self.shell('printf "%s" "$1" | _pop_status', malformed).stdout, "")

    def test_pop_retry_after_values(self):
        script = '''
responseHeaders="$1"
_time() { echo 1700000000; }
_sleep() { echo "sleep:$1"; }
_pop_retry_wait
'''
        cases = [
            ("", 2), ("X-Retry-After: 120", 2), ("Retry-After: invalid", 2),
            ("Retry-After: -1", 2), ("Retry-After: 1 20", 2),
            ("Retry-After: 0", 0), ("Retry-After: 000120", 120),
            ("HTTP/1.1 200 OK\r\nrEtRy-AfTeR:\t120 \t\r\n", 120),
            ("Retry-After: 600", 600), ("Retry-After: 601", 601),
            ("Retry-After: 1800", 1800), ("Retry-After: 18000", 18000),
            ("Retry-After: " + formatdate(1700000120, usegmt=True), 120),
            ("Retry-After: " + formatdate(1699999880, usegmt=True), 0),
            ("Retry-After: " + formatdate(1700018000, usegmt=True), 18000),
        ]
        for header, delay in cases:
            with self.subTest(header=header):
                result = self.shell(script, header)
                self.assertEqual(result.stdout.strip(), f"sleep:{delay}")

    def test_pop_order_continues_after_long_retry_delay(self):
        script = '''
Le_PopKey=synthetic-key
_pop_check_order_binding() { :; }
polls=0
_send_signed_request() {
  code=200; polls=$((polls + 1)); echo poll
  if [ "$polls" = 1 ]; then
    response='{"status":"pending","popKey":"synthetic-key"}'
  else
    response='{"status":"ready","popKey":"synthetic-key"}'
  fi
}
responseHeaders="Retry-After: $1"
_sleep() { echo "sleep:$1"; }
_pop_wait_ready
'''
        for delay in (601, 1800, 18000):
            with self.subTest(delay=delay):
                result = self.shell(script, delay)
                self.assertEqual(result.stdout.splitlines(), ["poll", f"sleep:{delay}", "poll"])

    def test_kem_rejection_cleans_up_after_pre_hook_only(self):
        for before_done, expected in (("", []), ("1", ["cleanup", "post:restore-service"])):
            script = '''
_pop_before_issue_done="$1"
_post_hook=restore-service
_clearup() { echo cleanup; }
_on_issue_err() { echo "post:$1"; }
_pop_fallback_issue dns_ali example.com "" ml-kem-768
'''
            result = self.shell(script, before_done, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout.splitlines(), expected)

    def test_challenge_key_must_match_order_before_proof(self):
        for status in ("pending", "valid"):
            for key in (None, "", "other-key", "synthetic-key="):
                with self.subTest(status=status, key=key):
                    challenge = {"type": "pop-01", "url": "https://ca.example/challenge", "status": status}
                    if key is not None:
                        challenge["key"] = key
                    auth = json.dumps({"status": status, "challenges": [challenge]}, separators=(",", ":"))
                    result = self.shell('''
Le_PopKey=synthetic-key; response="$1"
_pop_challenge_proof() { echo UNEXPECTED_PROOF >&2; return 1; }
_send_signed_request() { echo UNEXPECTED_NETWORK; return 1; }
_pop_complete_authorization https://ca.example/auth
''', auth, check=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Invalid PoP authorization or challenge key", result.stderr)
                    self.assertNotIn("UNEXPECTED_PROOF", result.stderr)
                    self.assertEqual(result.stdout, "")

    def test_unsupported_server_cannot_trigger_kem_csr(self):
        result = self.shell('DOMAIN_PATH="$1"; DOMAIN_CONF="$1/domain.conf"; CERT_KEY_PATH="$1/missing.key"; Le_ACME_Pop=1; _initpath() { :; }; _initAPI() { :; }; _createcsr() { echo UNEXPECTED_CSR; }; issue dns_ali example.com "" ml-kem-768', self.work, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CSR fallback is impossible", result.stderr)
        self.assertNotIn("UNEXPECTED_CSR", result.stdout)

    def test_challenge_dispatch_and_reject_mixed_modes(self):
        key, ciphertext, _ = self.kem_fixture("ML-KEM-768")
        challenge = {"challenge_ciphertext": b64url(ciphertext)}
        expected = self.shell('_pop_kem_proof "$1" "$2" "$3"', key, b64url(ciphertext), self.order).stdout
        actual = self.shell('_pop_challenge_proof "$1" "$2" "$3"', key, json.dumps(challenge, separators=(",", ":")), self.order)
        self.assertEqual(actual.stdout, expected)
        for invalid in ({}, {"popNonce": b64url(bytes(32))}, dict(challenge, popNonce=""), dict(challenge, popNonce=None)):
            result = self.shell('_pop_challenge_proof "$1" "$2" "$3"', key, json.dumps(invalid, separators=(",", ":")), self.order, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")

    def test_authorization_submits_kem_proof_and_polls(self):
        key, ciphertext, _ = self.kem_fixture("ML-KEM-768")
        spki = b64url(self.openssl("pkey", "-in", key, "-pubout", "-outform", "DER"))
        challenge = {"type": "pop-01", "url": "https://ca.example/challenge", "status": "pending", "key": spki, "challenge_ciphertext": b64url(ciphertext)}
        auth = {"identifier": {"type": "pop", "value": ""}, "status": "pending", "challenges": [challenge]}
        (self.work / "pop-new-order.json").write_bytes(self.order.read_bytes())
        proof = self.shell('_pop_kem_proof "$1" "$2" "$3"', key, b64url(ciphertext), self.order).stdout.strip()
        script = '''
CERT_KEY_PATH="$1"; DOMAIN_PATH="$2"; Le_PopKey="$3"; response="$4"
_sleep() { :; }
_send_signed_request() {
  printf '%s %s\\n' "$1" "$2"
  code=200
  if [ -n "$2" ]; then response='{"status":"processing"}'; else response='{"status":"valid"}'; fi
}
_pop_complete_authorization https://ca.example/auth
'''
        result = self.shell(script, key, self.work, spki, json.dumps(auth, separators=(",", ":")))
        self.assertEqual(result.stdout.splitlines(), [
            'https://ca.example/challenge {"proof":"' + proof + '"}',
            "https://ca.example/challenge ", "https://ca.example/auth ",
        ])
        challenge["key"] = "wrong-key"
        rejected = self.shell(script, key, self.work, spki, json.dumps(auth, separators=(",", ":")), check=False)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(rejected.stdout, "")

    def test_signature_proofs_still_verify(self):
        nonce = bytes(range(32))
        message = self.work / "message"
        message.write_bytes(b"ACME-pop-01-sig v1:" + nonce + hashlib.sha256(self.order.read_bytes()).digest())
        key = self.work / "signature-key.pem"
        public = self.work / "signature-public.pem"
        signature = self.work / "signature"
        for algorithm in ("RSA", "EC", "ED25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
            with self.subTest(algorithm=algorithm):
                options = []
                if algorithm == "RSA":
                    options = ["-pkeyopt", "rsa_keygen_bits:2048"]
                elif algorithm == "EC":
                    options = ["-pkeyopt", "ec_paramgen_curve:P-256"]
                self.openssl("genpkey", "-algorithm", algorithm, *options, "-out", key)
                self.openssl("pkey", "-in", key, "-pubout", "-out", public)
                challenge = json.dumps({"popNonce": b64url(nonce)}, separators=(",", ":"))
                proof = self.shell('_pop_challenge_proof "$1" "$2" "$3"', key, challenge, self.order).stdout.strip()
                raw = base64.urlsafe_b64decode(proof + "=" * (-len(proof) % 4))
                if algorithm == "EC":
                    self.assertEqual(len(raw), 64)
                    def integer(part):
                        value = part.lstrip(b"\0") or b"\0"
                        if value[0] & 128:
                            value = b"\0" + value
                        return b"\x02" + bytes([len(value)]) + value
                    integers = integer(raw[:32]) + integer(raw[32:])
                    raw = b"\x30" + bytes([len(integers)]) + integers
                signature.write_bytes(raw)
                if algorithm in ("RSA", "EC"):
                    opts = ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", "-sigopt", "rsa_mgf1_md:sha256"] if algorithm == "RSA" else []
                    self.openssl("dgst", "-sha256", "-verify", public, *opts, "-signature", signature, message)
                else:
                    self.openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public, "-sigfile", signature, "-in", message)
                    if algorithm.startswith("ML-DSA-"):
                        verify = [OPENSSL, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public), "-sigfile", str(signature), "-in", str(message), "-pkeyopt"]
                        self.openssl(*verify[1:], "context-string:")
                        wrong_context = subprocess.run(verify + ["context-string:ACME-pop-01-sig v1:"], capture_output=True)
                        self.assertNotEqual(wrong_context.returncode, 0)
                rejected = self.shell('_pop_challenge_proof "$1" "$2" "$3"', key, '{"popNonce":"' + b64url(nonce) + '","challenge_ciphertext":""}', self.order, check=False)
                self.assertNotEqual(rejected.returncode, 0)


if __name__ == "__main__":
    unittest.main()
