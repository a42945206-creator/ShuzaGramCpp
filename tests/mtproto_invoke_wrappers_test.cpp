// Tests for messages/invoke.hpp's UnwrapInvokeWrappers, exercised through
// the full MtprotoSession/crypto round trip (not just called directly) so
// this proves real clients' actual wire shape -- invokeWithLayer(layer,
// initConnection(..., query)) and nested variants -- reaches the same
// ping/registry dispatch a bare call does. Same "real crypto round trip,
// not just unit-call the function" discipline as mtproto_session_test.cpp.

#include <chrono>
#include <cstdio>
#include <string>

#include "shuzagram/mtproto/messages/invoke.hpp"
#include "shuzagram/mtproto/messages/system.hpp"
#include "shuzagram/mtproto/session.hpp"
#include "shuzagram/mtproto/unencrypted_message.hpp"

namespace {

using namespace shuzagram::mtproto;
using namespace shuzagram::mtproto::crypto;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

AuthKeyBytes RandomAuthKey() {
    AuthKeyBytes key{};
    const auto r = SystemRandomBytes(256);
    std::copy(r.begin(), r.end(), key.begin());
    return key;
}

EncryptedMessage ClientEncrypt(const AuthKeyBytes& key, std::int64_t salt, std::int64_t session_id,
                                const std::vector<std::uint8_t>& payload) {
    const std::int64_t msg_id = MessageId::New(std::chrono::system_clock::now(), MessageType::kFromClient).Raw();
    return EncryptMessage(key, salt, session_id, msg_id, /*seq_no=*/1, payload, Side::kClient);
}

std::vector<std::uint8_t> EncodePing(std::int64_t ping_id) {
    TLBuffer b;
    b.PutID(messages::Ping::kTypeId);
    b.PutLong(ping_id);
    return b.buf;
}

// Wraps `inner`'s already-encoded bytes in invokeWithLayer#da9b0d0d.
std::vector<std::uint8_t> WrapInvokeWithLayer(int layer, const std::vector<std::uint8_t>& inner) {
    TLBuffer b;
    b.PutID(messages::kInvokeWithLayerTypeId);
    b.PutInt32(layer);
    b.Put(inner);
    return b.buf;
}

std::vector<std::uint8_t> WrapInvokeWithoutUpdates(const std::vector<std::uint8_t>& inner) {
    TLBuffer b;
    b.PutID(messages::kInvokeWithoutUpdatesTypeId);
    b.Put(inner);
    return b.buf;
}

// Wraps `inner` in initConnection#c1cd5ea9 with flags=0 (no proxy, no
// params) and plausible-looking metadata fields.
std::vector<std::uint8_t> WrapInitConnection(const std::vector<std::uint8_t>& inner) {
    TLBuffer b;
    b.PutID(messages::kInitConnectionTypeId);
    b.PutUint32(0); // flags
    b.PutInt32(12345); // api_id
    b.PutBytes(std::vector<std::uint8_t>{'t', 'e', 's', 't'}); // device_model
    b.PutBytes(std::vector<std::uint8_t>{'1', '.', '0'});      // system_version
    b.PutBytes(std::vector<std::uint8_t>{'1', '.', '0'});      // app_version
    b.PutBytes({});                                            // system_lang_code
    b.PutBytes({});                                            // lang_pack
    b.PutBytes(std::vector<std::uint8_t>{'e', 'n'});           // lang_code
    b.Put(inner);
    return b.buf;
}

// Same shape as WrapInitConnection but with the proxy flag (bit 0) set and
// no actual InputClientProxy bytes following -- this project doesn't
// decode that type, so the test only needs the flag bit, never valid proxy
// data (UnwrapInvokeWrappers must throw before trying to read it).
std::vector<std::uint8_t> WrapInitConnectionWithProxyFlag() {
    TLBuffer b;
    b.PutID(messages::kInitConnectionTypeId);
    b.PutUint32(1u << 0); // flags: proxy present
    b.PutInt32(12345);
    b.PutBytes({});
    b.PutBytes({});
    b.PutBytes({});
    b.PutBytes({});
    b.PutBytes({});
    b.PutBytes({});
    return b.buf;
}

EncryptedMessageData Roundtrip(MtprotoSession& server, const AuthKeyBytes& key, std::int64_t salt,
                                std::int64_t session_id, const std::vector<std::uint8_t>& payload) {
    const auto replies = server.HandleEncrypted(ClientEncrypt(key, salt, session_id, payload));
    Check(replies.size() == 1, "produces exactly one reply");
    if (replies.empty()) throw std::runtime_error("no reply");
    return DecryptMessage(key, replies[0], Side::kClient);
}

void TestBarePingStillWorks() {
    const AuthKeyBytes key = RandomAuthKey();
    MtprotoSession server(key, 111, 222, Side::kServer);
    const auto reply = Roundtrip(server, key, 222, 111, EncodePing(1));
    TLBuffer b;
    b.buf = reply.message_data;
    b.ConsumeID(messages::Pong::kTypeId);
    Check(true, "a bare (unwrapped) ping is unaffected by adding unwrap support");
}

void TestInvokeWithLayerWrappedPing() {
    const AuthKeyBytes key = RandomAuthKey();
    MtprotoSession server(key, 111, 222, Side::kServer);
    const auto reply = Roundtrip(server, key, 222, 111, WrapInvokeWithLayer(177, EncodePing(2)));
    TLBuffer b;
    b.buf = reply.message_data;
    b.ConsumeID(messages::Pong::kTypeId);
    b.Long(); // msg_id
    Check(b.Long() == 2, "invokeWithLayer(177, ping) unwraps and dispatches to the real ping");
}

void TestInitConnectionWrappedPing() {
    const AuthKeyBytes key = RandomAuthKey();
    MtprotoSession server(key, 111, 222, Side::kServer);
    const auto reply = Roundtrip(server, key, 222, 111, WrapInitConnection(EncodePing(3)));
    TLBuffer b;
    b.buf = reply.message_data;
    b.ConsumeID(messages::Pong::kTypeId);
    b.Long();
    Check(b.Long() == 3, "initConnection(..., ping) unwraps and dispatches to the real ping");
}

void TestDeeplyNestedWrappers() {
    const AuthKeyBytes key = RandomAuthKey();
    MtprotoSession server(key, 111, 222, Side::kServer);
    // invokeWithLayer(177, initConnection(..., invokeWithoutUpdates(ping)))
    const auto nested = WrapInvokeWithLayer(177, WrapInitConnection(WrapInvokeWithoutUpdates(EncodePing(4))));
    const auto reply = Roundtrip(server, key, 222, 111, nested);
    TLBuffer b;
    b.buf = reply.message_data;
    b.ConsumeID(messages::Pong::kTypeId);
    b.Long();
    Check(b.Long() == 4, "three levels of nested invoke wrappers all unwrap correctly");
}

void TestWrappedCallReachesRegisteredHandler() {
    const AuthKeyBytes key = RandomAuthKey();
    constexpr std::uint32_t kDemoMethodId = 0x12345678;
    RpcHandlerRegistry registry;
    registry.Register(kDemoMethodId, [](std::uint32_t, TLBuffer&, const RpcContext&) -> std::vector<std::uint8_t> {
        messages::Pong fake_response;
        fake_response.msg_id = 0;
        fake_response.ping_id = 999;
        TLBuffer out;
        fake_response.Encode(out);
        return out.buf;
    });
    MtprotoSession server(key, 111, 222, Side::kServer, &registry);

    TLBuffer call;
    call.PutID(kDemoMethodId);
    const auto reply = Roundtrip(server, key, 222, 111, WrapInvokeWithLayer(177, call.buf));
    TLBuffer b;
    b.buf = reply.message_data;
    b.ConsumeID(messages::RpcResult::kTypeId);
    b.Long(); // req_msg_id
    b.ConsumeID(messages::Pong::kTypeId);
    b.Long();
    Check(b.Long() == 999, "a wrapped call reaches a registered business-method handler, same as a bare call would");
}

void TestInitConnectionWithProxyFlagIsRejectedNotCrashed() {
    const AuthKeyBytes key = RandomAuthKey();
    MtprotoSession server(key, 111, 222, Side::kServer);
    const auto reply = Roundtrip(server, key, 222, 111, WrapInitConnectionWithProxyFlag());
    TLBuffer b;
    b.buf = reply.message_data;
    b.ConsumeID(messages::RpcResult::kTypeId);
    b.Long();
    b.ConsumeID(messages::RpcError::kTypeId);
    const int code = b.Int32();
    Check(code == 500, "initConnection with an unsupported proxy field gets a clean error reply, not a crash/hang");
}

} // namespace

int main() {
    TestBarePingStillWorks();
    TestInvokeWithLayerWrappedPing();
    TestInitConnectionWrappedPing();
    TestDeeplyNestedWrappers();
    TestWrappedCallReachesRegisteredHandler();
    TestInitConnectionWithProxyFlagIsRejectedNotCrashed();
    if (g_failures == 0) {
        std::printf("all mtproto invoke-wrapper tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto invoke-wrapper test(s) failed\n", g_failures);
    return 1;
}
