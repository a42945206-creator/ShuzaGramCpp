#pragma once

#include <chrono>
#include <cstdint>
#include <vector>

#include "shuzagram/mtproto/tl_buffer.hpp"

// Port of proto/unencrypted_message.go and proto/message_id.go: the plain
// (auth_key_id == 0) message envelope every handshake message travels in,
// and the message_id scheme used to generate/validate it.
namespace shuzagram::mtproto {

enum class MessageType { kUnknown, kFromClient, kServerResponse, kFromServer };

// message_id low bits encode the message's direction/role (the "yield"),
// both so a message id is never ambiguous about who produced it and so it
// still carries an approximate creation timestamp in its high bits.
// https://core.telegram.org/mtproto/description#message-identifier-msg-id
class MessageId {
public:
    static MessageId FromRaw(std::int64_t raw) { return MessageId(raw); }

    static MessageId New(std::chrono::system_clock::time_point now, MessageType type) {
        return NewFromNanos(std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count(),
                             type);
    }

    static MessageId NewFromNanos(std::int64_t now_nanos, MessageType type) {
        int yield;
        switch (type) {
            case MessageType::kFromClient: yield = kYieldClient; break;
            case MessageType::kFromServer: yield = kYieldFromServer; break;
            case MessageType::kServerResponse: yield = kYieldServerResponse; break;
            default: yield = kYieldClient; break;
        }
        std::int64_t id = Compute(now_nanos, yield);
        // A client message id created exactly on an integral second would
        // otherwise have a zero low-32-bit fractional part, the value
        // MTProto reserves to keep replay protection effective -- nudge it
        // to the first valid client tick, preserving both timestamp and type.
        if (Type(id) == MessageType::kFromClient && static_cast<std::uint32_t>(id) == 0) id += kMessageIdModulo;
        return MessageId(id);
    }

    [[nodiscard]] std::int64_t Raw() const { return raw_; }

    [[nodiscard]] MessageType Type() const { return Type(raw_); }

private:
    explicit MessageId(std::int64_t raw) : raw_(raw) {}

    static constexpr int kYieldClient = 0;
    static constexpr int kYieldServerResponse = 1;
    static constexpr int kYieldFromServer = 3;
    static constexpr std::int64_t kMessageIdModulo = 4;

    static std::int64_t Compute(std::int64_t now_nanos, int yield) {
        constexpr std::int64_t kNano = 1'000'000'000;
        std::int64_t int_part = now_nanos / kNano;
        std::int64_t frac_part = now_nanos % kNano;
        frac_part &= -kMessageIdModulo;
        frac_part += yield;
        return (int_part << 32) | (frac_part & 0xFFFFFFFFLL);
    }

    static MessageType Type(std::int64_t raw) {
        switch (((raw % kMessageIdModulo) + kMessageIdModulo) % kMessageIdModulo) {
            case kYieldClient: return MessageType::kFromClient;
            case kYieldServerResponse: return MessageType::kServerResponse;
            case kYieldFromServer: return MessageType::kFromServer;
            default: return MessageType::kUnknown;
        }
    }

    std::int64_t raw_;
};

// UnencryptedMessage is the plaintext (auth_key_id == 0) frame every
// handshake message rides in: auth_key_id(8, ==0) + message_id(8) +
// length(4) + data.
struct UnencryptedMessage {
    std::int64_t message_id = 0;
    std::vector<std::uint8_t> message_data;

    void Encode(TLBuffer& b) const {
        b.PutLong(0);
        b.PutLong(message_id);
        b.PutInt32(static_cast<std::int32_t>(message_data.size()));
        b.Put(message_data);
    }

    // Throws BufferUnderrunError / std::runtime_error on a malformed frame,
    // including a non-zero auth_key_id (a caller expecting a handshake
    // frame that instead reads an encrypted one should peek auth_key_id
    // itself before calling Decode -- see server_exchange.cpp).
    void Decode(TLBuffer& b) {
        const std::int64_t auth_key_id = b.Long();
        if (auth_key_id != 0) throw std::runtime_error("unexpected non-zero auth_key_id in plaintext message");
        message_id = b.Long();
        const std::int32_t data_len = b.Int32();
        if (data_len < 0) throw std::runtime_error("negative plaintext message length");
        if (static_cast<std::size_t>(data_len) > b.Len()) throw BufferUnderrunError();
        message_data.resize(static_cast<std::size_t>(data_len));
        b.ConsumeN(message_data.data(), message_data.size());
    }
};

} // namespace shuzagram::mtproto
