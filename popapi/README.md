# PoP key providers

Use `--pop-provider <name>` to load `popapi/<name>.sh`. The provider is a
key-operation adapter; acme.sh still constructs the draft-01 PoP message,
HKDF and HMAC.

The provider functions are called with base64url values so binary key
operations do not pass through shell arguments as raw bytes:

```sh
<name>_get_public_key <key-id>
<name>_sign <key-id> <algorithm> <message-base64url>
<name>_decap <key-id> <algorithm> <ciphertext-base64url>
```

`get_public_key` returns canonical DER SubjectPublicKeyInfo encoded as
base64url. `sign` returns the raw signature encoded as base64url. ECDSA must
return fixed-width `r || s`, rather than ASN.1 DER. `decap` returns the
base64url encoding of the 32-byte shared secret.

Example:

```sh
./acme.sh --issue --acme-pop \
  --pop-provider pop_command --pop-key-id device-42 \
  --dns dns_ali -d example.com
```

The bundled `pop_command` provider calls executables configured through
`POP_CommandPublicKey`, `POP_CommandSign`, and `POP_CommandDecap`. The sign
executable receives `POP_KEY_ID`, `POP_ALGORITHM`, and `POP_MESSAGE`; the
decapsulation executable receives `POP_KEY_ID`, `POP_ALGORITHM`, and
`POP_CIPHERTEXT`.
