#pragma once

#include <array>
#include <cstdint>
#include <exception>
#include <vector>

// Port of exchange.UnexpectedEncryptedError (exchange/server_flow.go):
// thrown when a frame read during the handshake turns out to carry a
// non-zero auth_key_id -- the peer is reusing an already-established key
// instead of performing key exchange. The Go source's own comment on this
// (which the caller-side integration this project hasn't built yet must
// respect) explains why this can't just be treated as an exchange failure:
//
// "The caller should resolve the key and handle Frame as an encrypted
// message rather than treating it as an exchange failure. In particular,
// callers must not blindly reply with auth_key_not_found (-404): clients
// such as Telegram Desktop treat a -404 on a temporary key as 'key
// destroyed', discard it and re-run key exchange, which leads to a
// reconnect/key-exchange storm."
namespace shuzagram::mtproto {

class UnexpectedEncryptedFrameError : public std::exception {
public:
    UnexpectedEncryptedFrameError(std::array<std::uint8_t, 8> auth_key_id, std::vector<std::uint8_t> frame)
        : auth_key_id_(auth_key_id), frame_(std::move(frame)) {}

    const char* what() const noexcept override { return "unexpected encrypted message during key exchange"; }
    [[nodiscard]] const std::array<std::uint8_t, 8>& auth_key_id() const { return auth_key_id_; }
    [[nodiscard]] const std::vector<std::uint8_t>& frame() const { return frame_; }

private:
    std::array<std::uint8_t, 8> auth_key_id_;
    std::vector<std::uint8_t> frame_;
};

} // namespace shuzagram::mtproto
