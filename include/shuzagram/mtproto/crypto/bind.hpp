#pragma once

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

#include "shuzagram/mtproto/crypto/message_cipher.hpp"
#include "shuzagram/mtproto/crypto/random.hpp"
#include "shuzagram/mtproto/messages/bind.hpp"

// Port of gotd/td's crypto/bind.go: the special binding-message envelope
// auth.bindTempAuthKey's encrypted_message field uses. Distinct from
// ordinary MTProto 2.0 traffic (message_cipher.hpp) in three ways the
// protocol spec requires: it always uses the legacy v1 KDF (kdf_v1.hpp),
// seq_no is hardcoded to 0, and there's no salt/session_id in the envelope
// (session_id/salt aren't part of what's being proven -- only "does the
// caller possess the permanent key").
// See https://core.telegram.org/api/pfs#binding-message-contents.
namespace shuzagram::mtproto::crypto {

// Thrown by DecryptBindAuthKeyInner on ANY validation failure -- wrong
// auth_key_id, misaligned/too-short ciphertext, msg_key integrity mismatch,
// or a malformed/wrong-type inner structure. Deliberately not distinguishing
// the reason, matching internal/app/auth/service.go's decryptBindAuthKeyInner,
// which collapses every failure mode here into the single public
// ENCRYPTED_MESSAGE_INVALID RPC error (never leaking which check failed to
// an unauthenticated-for-this-key caller).
class BindEncryptedMessageInvalidError : public std::runtime_error {
public:
    BindEncryptedMessageInvalidError() : std::runtime_error("encrypted message invalid") {}
};

// Builds the encrypted_message field of an auth.bindTempAuthKey request:
// TL-encodes `inner`, wraps it in the binding envelope (16 bytes random +
// msg_id + seq_no=0 + length + payload, then padded to a block boundary),
// and IGE-encrypts it under perm_key via the legacy v1 KDF. This is what a
// genuine client does -- ported here so tests can build a realistic request
// without a real client implementation; the server itself only ever calls
// DecryptBindAuthKeyInner below. Throws std::invalid_argument if perm_key is
// all-zero (an obviously-uninitialized key, never a real one).
std::vector<std::uint8_t> EncryptBindMessage(const AuthKeyBytes& perm_key, std::int64_t msg_id,
                                              const messages::BindAuthKeyInner& inner,
                                              const RandomFill& rand = SystemRandomFill);

// Decrypts and integrity-checks one auth.bindTempAuthKey encrypted_message,
// proving only that its sender possesses perm_key (the caller is
// responsible for having already loaded the row named by the request's
// perm_auth_key_id and confirmed it's actually a permanent key --
// store::AuthKeyData::expires_at == 0 -- before calling this). Throws
// BindEncryptedMessageInvalidError on any failure.
messages::BindAuthKeyInner DecryptBindAuthKeyInner(const AuthKeyBytes& perm_key,
                                                    const std::vector<std::uint8_t>& encrypted_message);

} // namespace shuzagram::mtproto::crypto
