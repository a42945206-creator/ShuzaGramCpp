#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "shuzagram/mtproto/crypto/aes_ctr.hpp"

// Port of github.com/iamxvbaba/td's mtproxy/obfuscated2 package (keys.go,
// keys_util.go, server.go) -- MTProto's "transport obfuscation": the client
// sends 64 bytes that look uniformly random (a real MTProto frame never
// does), which double as AES-256-CTR key material for both directions plus
// an encrypted 4-byte inner-protocol tag + 2-byte DC id. See
// NOTES/obfuscated2-transport-plan.md for why this exists (real clients
// default to it) and what's deliberately not ported (the client side --
// generateKeys/generateInit -- and MTProxy secret-mode extensions this
// project, not being a proxy, never needs).
namespace shuzagram::mtproto::transport {

struct Obfuscated2Metadata {
    std::array<std::uint8_t, 4> protocol{};
    std::uint16_t dc = 0;
};

struct Obfuscated2Keys {
    crypto::Aes256CtrStream encrypt;
    crypto::Aes256CtrStream decrypt;
};

// createStreams (keys.go): derives the two AES-256-CTR streams from the raw
// 64-byte init blob (exactly as sent on the wire -- see AcceptObfuscated2's
// own comment for why decrypting it again is safe) plus an optional MTProxy
// secret (empty = no secret, this project's own real-world case). Exposed
// separately from AcceptObfuscated2 because it's independently verified
// against gotd/td's own TestEncrypt vector (see
// tests/mtproto_obfuscated2_test.cpp) before the accept-side role-swap and
// tag-extraction logic is layered on top.
Obfuscated2Keys CreateObfuscated2Streams(const std::array<std::uint8_t, 64>& init,
                                          const std::vector<std::uint8_t>& secret);

struct Obfuscated2AcceptResult {
    Obfuscated2Keys keys; // already role-swapped: .decrypt reads client bytes, .encrypt writes to the client
    Obfuscated2Metadata metadata;
};

// Accept (server.go): wire_init is the 64 bytes read verbatim off the
// socket (the client's random init with its last 8 bytes replaced by the
// client's own encrypt-stream applied to the real protocol tag + dc). Never
// throws on a malformed/random tag -- the caller decides what to do with an
// unrecognized metadata.protocol, matching detectObfuscatedProtocol's own
// separation of concerns in the Go source.
Obfuscated2AcceptResult AcceptObfuscated2(const std::array<std::uint8_t, 64>& wire_init,
                                           const std::vector<std::uint8_t>& secret);

} // namespace shuzagram::mtproto::transport
