#!/usr/bin/env sh

# Generic PoP provider bridge. Configure executable paths in account.conf or
# the environment. Each executable must print one canonical base64url value:
#   POP_CommandPublicKey key_ref -> DER SubjectPublicKeyInfo
#   POP_CommandSign receives POP_KEY_REF, POP_ALGORITHM and POP_MESSAGE
#   POP_CommandDecap receives POP_KEY_REF, POP_ALGORITHM and POP_CIPHERTEXT

pop_command_info='Generic command provider
Options:
 POP_CommandPublicKey  Executable returning base64url DER SPKI for a key reference
 POP_CommandSign       Executable returning a base64url raw signature
 POP_CommandDecap      Executable returning a base64url 32-byte shared secret
'

pop_command_get_public_key() {
  POP_CommandPublicKey="${POP_CommandPublicKey:-$(_readaccountconf_mutable POP_CommandPublicKey)}"
  if [ -z "$POP_CommandPublicKey" ]; then
    _err "POP_CommandPublicKey is not configured."
    return 1
  fi
  _saveaccountconf_mutable POP_CommandPublicKey "$POP_CommandPublicKey"
  "$POP_CommandPublicKey" "$1"
}

pop_command_sign() {
  POP_CommandSign="${POP_CommandSign:-$(_readaccountconf_mutable POP_CommandSign)}"
  if [ -z "$POP_CommandSign" ]; then
    _err "POP_CommandSign is not configured."
    return 1
  fi
  _saveaccountconf_mutable POP_CommandSign "$POP_CommandSign"
  POP_KEY_REF="$1" POP_ALGORITHM="$2" POP_MESSAGE="$3" \
    "$POP_CommandSign"
}

pop_command_decap() {
  POP_CommandDecap="${POP_CommandDecap:-$(_readaccountconf_mutable POP_CommandDecap)}"
  if [ -z "$POP_CommandDecap" ]; then
    _err "POP_CommandDecap is not configured."
    return 1
  fi
  _saveaccountconf_mutable POP_CommandDecap "$POP_CommandDecap"
  POP_KEY_REF="$1" POP_ALGORITHM="$2" POP_CIPHERTEXT="$3" \
    "$POP_CommandDecap"
}
