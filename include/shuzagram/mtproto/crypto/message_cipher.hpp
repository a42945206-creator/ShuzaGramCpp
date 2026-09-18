#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "shuzagram/mtproto/crypto/random.hpp"
#include "shuzagram/mtproto/tl_buffer.hpp"

// Port of gotd/td's crypto/{key,keys,cipher,cipher_encrypt,cipher_decrypt,
// encrypted_message,encrypted_message_data}.go: MTProto 2.0 encryption for
// ordinary (post-handshake) messages, keyed by the auth_key
// shuzagram::mtproto::ServerExchange::Run produces.
//
// https://core.telegram.org/mtproto/description#defining-aes-key-and-initialization-vector
namespace shuzagram::mtproto::crypto {

using AuthKeyBytes = std::array<std::uint8_t, 256>;

// Side determines which 36-byte slice of auth_key (offset 0 or 8) feeds the
// key/iv derivation and msg_key computation, so a message encrypted by one
// side can never be replayed back as if sent by the other.
enum class Side { kClient, kServer };
inline Side OppositeSide(Side s) { return s == Side::kClient ? Side::kServer : Side::kClient; }

// auth_key_id = SHA1(auth_key)[12:20]. Every persisted AuthKeyData::id this
// project stores is exactly this value -- see store::postgres::AuthKeyStore
// and store::detail::AuthKeyIDToInt64/FromInt64, which interpret the same
// 8 bytes as a little-endian int64 for the database.
std::array<std::uint8_t, 8> AuthKeyId(const AuthKeyBytes& auth_key);
// aux_hash = SHA1(auth_key)[0:8]. Used by auth.bindTempAuthKey (not yet
// ported) to prove ownership of the permanent key; included here because
// it's the same one-line derivation as AuthKeyId, not because anything
// calls it yet.
std::array<std::uint8_t, 8> AuthKeyAuxHash(const AuthKeyBytes& auth_key);

// msg_key = substr(SHA256(substr(auth_key, 88+x, 32) + plaintext_padded), 8, 16),
// x = 0 for Client, 8 for Server.
Int128 MessageKey(const AuthKeyBytes& auth_key, const std::vector<std::uint8_t>& plaintext_padded, Side side);

// (aes_key, aes_iv) for AES-256-IGE, derived from auth_key and msg_key.
void DeriveMessageKeys(const AuthKeyBytes& auth_key, const Int128& msg_key, Side side, std::vector<std::uint8_t>& key,
                        std::vector<std::uint8_t>& iv);

// MTProto 2.0 requires 12..1024 bytes of padding, total length a multiple
// of 16; the low 4 bits of rand_byte add 0..15 extra 16-byte blocks so the
// encrypted length isn't a deterministic fingerprint of the plaintext
// length. See countPadding's own comment in cipher_encrypt.go for why.
int CountPadding(int plaintext_len, std::uint8_t rand_byte);

// The plaintext structure encrypted inside EncryptedMessage.encrypted_data.
struct EncryptedMessageData {
    std::int64_t salt = 0;
    std::int64_t session_id = 0;
    std::int64_t message_id = 0;
    std::int32_t seq_no = 0;
    // The real inner (TL-encoded) RPC message, already stripped of
    // padding -- what Go's EncryptedMessageData.Data() returns, not the
    // raw MessageDataWithPadding.
    std::vector<std::uint8_t> message_data;
};

// The wire envelope: auth_key_id(8) + msg_key(16) + encrypted_data(N, a
// multiple of 16).
struct EncryptedMessage {
    std::array<std::uint8_t, 8> auth_key_id{};
    Int128 msg_key{};
    std::vector<std::uint8_t> encrypted_data;

    void Encode(TLBuffer& b) const;
    // Consumes the rest of the buffer as encrypted_data.
    void Decode(TLBuffer& b);
};

// Encrypts message_data (the inner RPC payload) as `encrypt_as`, ready to
// send on the wire.
EncryptedMessage EncryptMessage(const AuthKeyBytes& auth_key, std::int64_t salt, std::int64_t session_id,
                                 std::int64_t message_id, std::int32_t seq_no,
                                 const std::vector<std::uint8_t>& message_data, Side encrypt_as,
                                 const RandomFill& rand = SystemRandomFill);

// Decrypts and validates an EncryptedMessage that the OPPOSITE side of
// `decrypt_as` is expected to have produced (a server passes kServer here
// to decrypt what a client sent, matching Go's Cipher.encryptSide /
// DecryptSide() convention). Throws std::runtime_error on any validation
// failure: wrong auth_key_id, msg_key mismatch (the AEAD-like integrity
// check -- a forged or corrupted ciphertext decrypts to a plaintext whose
// recomputed msg_key won't match the one on the wire), or an invalid
// message_data_len/padding.
EncryptedMessageData DecryptMessage(const AuthKeyBytes& auth_key, const EncryptedMessage& encrypted, Side decrypt_as);

} // namespace shuzagram::mtproto::crypto
