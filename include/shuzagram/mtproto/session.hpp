#pragma once

#include <cstdint>
#include <vector>

#include "shuzagram/mtproto/crypto/message_cipher.hpp"
#include "shuzagram/mtproto/rpc_dispatch.hpp"

// The piece that turns "decrypt one EncryptedMessage" into an actual
// stateful session: unwrapping msg_container, answering ping with pong,
// dispatching anything else as an RPC call (rpc_result/rpc_error), and
// encrypting the replies with the same auth_key. See
// NOTES/rpc-dispatch-plan.md for exactly what's simplified here versus the
// Go source's full session/replay-protection machinery
// (internal/mtprotoedge/{encrypted,decrypt}.go, ~1800 lines) -- this is the
// dispatch mechanism, not a production-grade session layer.
namespace shuzagram::mtproto {

class MtprotoSession {
public:
    // my_side is which role THIS session encrypts as when replying (a
    // server passes kServer); decrypting incoming messages uses the
    // opposite side, matching crypto::DecryptMessage's own convention.
    // session_id is only an initial value: real MTProto has the client
    // establish it, and HandleEncrypted re-syncs this session's own
    // session_id_ from every incoming message's own field, so 0 is a fine
    // placeholder when a server doesn't know it yet at construction time.
    MtprotoSession(crypto::AuthKeyBytes auth_key, std::int64_t session_id, std::int64_t server_salt,
                    crypto::Side my_side, const RpcHandlerRegistry* registry = nullptr);

    // Decrypts and validates `incoming`, dispatches whatever it contained
    // (a single object, or a msg_container's worth of them), and returns
    // zero or more ready-to-send EncryptedMessages (one per reply -- this
    // round doesn't bundle multiple replies back into one outgoing
    // container). Throws std::runtime_error on a decrypt/validation
    // failure (wrong auth_key, corrupted ciphertext, non-monotonic
    // msg_id -- see the simplifications noted in
    // NOTES/rpc-dispatch-plan.md); the caller decides whether that means
    // closing the connection.
    std::vector<crypto::EncryptedMessage> HandleEncrypted(const crypto::EncryptedMessage& incoming);

private:
    struct InnerMessage {
        std::int64_t msg_id;
        std::vector<std::uint8_t> body;
    };

    // Returns the pre-encoded response object for one inner message, or an
    // empty vector if no reply is warranted (e.g. msgs_ack).
    std::vector<std::uint8_t> DispatchOne(std::int64_t msg_id, const std::vector<std::uint8_t>& body);

    std::int64_t NextSeqNo(bool content_related);
    crypto::EncryptedMessage EncryptOutgoing(const std::vector<std::uint8_t>& body);

    crypto::AuthKeyBytes auth_key_;
    std::int64_t session_id_;
    std::int64_t server_salt_;
    crypto::Side my_side_;
    const RpcHandlerRegistry* registry_;

    std::int64_t last_seen_msg_id_ = 0; // basic monotonic replay guard, see NOTES
    std::int64_t content_seq_counter_ = 0; // the official seq_no formula's "N"
};

} // namespace shuzagram::mtproto
