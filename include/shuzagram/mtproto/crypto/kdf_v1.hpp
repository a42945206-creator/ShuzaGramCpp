#pragma once

#include <vector>

#include "shuzagram/mtproto/crypto/message_cipher.hpp"

// Port of gotd/td's crypto/kdf_v1.go + the x=0 ("client side") schedule from
// crypto/keys_old.go: the legacy MTProto 1.0 key derivation that
// auth.bindTempAuthKey's encrypted_message envelope deliberately keeps using
// even though ordinary MTProto traffic is 2.0 (message_cipher.hpp). See
// https://core.telegram.org/method/auth.bindTempAuthKey and
// https://core.telegram.org/api/pfs#binding-message-contents.
namespace shuzagram::mtproto::crypto {

// msg_key = substr(SHA1(plaintext), 4, 16).
Int128 MessageKeyV1(const std::vector<std::uint8_t>& plaintext);

// (aes_key, aes_iv) for AES-256-IGE, always using the x=0 schedule --
// binding fixes this regardless of which end is encrypting/decrypting, per
// the protocol spec (there is no separate "server side" variant for this
// specific envelope).
void KeysV1(const AuthKeyBytes& auth_key, const Int128& msg_key, std::vector<std::uint8_t>& key,
            std::vector<std::uint8_t>& iv);

} // namespace shuzagram::mtproto::crypto
