#include "shuzagram/mtproto/transport/obfuscated2.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace shuzagram::mtproto::transport {
namespace {

// getDecryptInit (keys_util.go): copy init[8:56] (48 bytes) and reverse it.
std::array<std::uint8_t, 48> ReversedMiddle(const std::array<std::uint8_t, 64>& init) {
    std::array<std::uint8_t, 48> out{};
    std::copy(init.begin() + 8, init.begin() + 56, out.begin());
    std::reverse(out.begin(), out.end());
    return out;
}

// crypto.SHA256(a, b) from the Go source: SHA256(a || b), via the same
// non-deprecated EVP API this project already uses in message_cipher.cpp's
// Sha256TwoPart.
std::vector<std::uint8_t> Sha256(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    std::vector<std::uint8_t> out(EVP_MAX_MD_SIZE);
    unsigned int out_len = 0;
    const bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) &&
                     EVP_DigestUpdate(ctx, a.data(), a.size()) && EVP_DigestUpdate(ctx, b.data(), b.size()) &&
                     EVP_DigestFinal_ex(ctx, out.data(), &out_len);
    if (ctx) EVP_MD_CTX_free(ctx);
    if (!ok) throw std::runtime_error("SHA256 (two-part) failed");
    out.resize(out_len);
    return out;
}

} // namespace

Obfuscated2Keys CreateObfuscated2Streams(const std::array<std::uint8_t, 64>& init,
                                          const std::vector<std::uint8_t>& secret) {
    std::vector<std::uint8_t> encrypt_key(init.begin() + 8, init.begin() + 40);
    std::vector<std::uint8_t> encrypt_iv(init.begin() + 40, init.begin() + 56);

    const auto rev = ReversedMiddle(init);
    std::vector<std::uint8_t> decrypt_key(rev.begin(), rev.begin() + 32);
    std::vector<std::uint8_t> decrypt_iv(rev.begin() + 32, rev.begin() + 48);

    if (!secret.empty()) {
        // Only the first 16 bytes of a longer secret are used, matching the
        // Go source exactly (secret = secret[0:16]).
        const std::vector<std::uint8_t> secret16(secret.begin(), secret.begin() + 16);
        encrypt_key = Sha256(encrypt_key, secret16);
        decrypt_key = Sha256(decrypt_key, secret16);
    }

    return Obfuscated2Keys{crypto::Aes256CtrStream(encrypt_key, encrypt_iv),
                            crypto::Aes256CtrStream(decrypt_key, decrypt_iv)};
}

Obfuscated2AcceptResult AcceptObfuscated2(const std::array<std::uint8_t, 64>& wire_init,
                                           const std::vector<std::uint8_t>& secret) {
    auto keys = CreateObfuscated2Streams(wire_init, secret);
    // Swap to match the client's streams: the client encrypted its outgoing
    // bytes (including this header's tail) with what CreateObfuscated2Streams
    // calls "encrypt", so the server's "decrypt" (used to read client bytes)
    // must be that same stream, and vice versa for the server's own writes.
    Obfuscated2AcceptResult result{Obfuscated2Keys{std::move(keys.decrypt), std::move(keys.encrypt)},
                                    Obfuscated2Metadata{}};

    // Decrypting the full 64-byte wire_init (not just bytes 56:64) is
    // deliberate, not wasted work: bytes 0:56 were never encrypted by the
    // client (they ARE the key material, sent in the clear), so decrypting
    // them produces garbage that's simply discarded -- but doing so is the
    // only way to advance the CTR keystream to the correct position (64)
    // before any real payload bytes are decrypted, exactly like the Go
    // source's own k.decrypt.XORKeyStream(decrypted[:], buf) over the whole
    // buffer.
    std::array<std::uint8_t, 64> decrypted{};
    result.keys.decrypt.XorKeyStream(decrypted.data(), wire_init.data(), decrypted.size());

    std::copy(decrypted.begin() + 56, decrypted.begin() + 60, result.metadata.protocol.begin());
    result.metadata.dc = static_cast<std::uint16_t>(decrypted[60]) |
                          (static_cast<std::uint16_t>(decrypted[61]) << 8);
    return result;
}

} // namespace shuzagram::mtproto::transport
