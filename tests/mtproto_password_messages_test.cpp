// Wire-format checks for the auth.checkPassword / account.getPassword TL
// structs (messages/password.hpp), same discipline as
// mtproto_auth_messages_test.cpp: decode against a hand-built buffer,
// encode checked byte-for-byte against a hand-assembled expected buffer.

#include <cstdio>
#include <string>

#include "shuzagram/mtproto/messages/password.hpp"

namespace {

using namespace shuzagram::mtproto;
using namespace shuzagram::mtproto::messages;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

void PutTLBytes(TLBuffer& b, const std::vector<std::uint8_t>& v) { b.PutBytes(v); }

void TestDecodeInputCheckPasswordEmpty() {
    TLBuffer b;
    b.PutID(0x9880f658); // inputCheckPasswordEmpty
    AuthCheckPasswordRequest req;
    req.DecodeBare(b);
    Check(req.check.empty, "inputCheckPasswordEmpty decodes to PasswordCheck{empty=true}");
    Check(b.buf.empty(), "no leftover bytes after decoding inputCheckPasswordEmpty");
}

void TestDecodeInputCheckPasswordSrp() {
    TLBuffer b;
    b.PutID(0xd27ff082); // inputCheckPasswordSRP
    b.PutLong(123456789);
    PutTLBytes(b, {1, 2, 3, 4});
    PutTLBytes(b, {5, 6, 7, 8, 9});

    AuthCheckPasswordRequest req;
    req.DecodeBare(b);
    Check(!req.check.empty, "inputCheckPasswordSRP decodes to a non-empty check");
    Check(req.check.srp_id == 123456789, "decodes srp_id");
    Check((req.check.a == std::vector<std::uint8_t>{1, 2, 3, 4}), "decodes A");
    Check((req.check.m1 == std::vector<std::uint8_t>{5, 6, 7, 8, 9}), "decodes M1");
    Check(b.buf.empty(), "no leftover bytes after decoding inputCheckPasswordSRP");
}

void TestEncodePasswordAlgoModPow() {
    shuzagram::domain::PasswordAlgo algo;
    algo.salt1 = {1, 2, 3};
    algo.salt2 = {4, 5};
    algo.g = 3;
    algo.p = {6, 7, 8, 9};

    TLBuffer out;
    EncodePasswordAlgo(out, algo);

    TLBuffer expected;
    expected.PutID(0x3a912d4a);
    PutTLBytes(expected, algo.salt1);
    PutTLBytes(expected, algo.salt2);
    expected.PutInt32(3);
    PutTLBytes(expected, algo.p);
    Check(out.buf == expected.buf, "EncodePasswordAlgo encodes the ModPow variant with fields in order");
}

void TestEncodePasswordAlgoUnknownWhenEmpty() {
    shuzagram::domain::PasswordAlgo algo; // p empty
    TLBuffer out;
    EncodePasswordAlgo(out, algo);
    TLBuffer expected;
    expected.PutID(0xd45ab096);
    Check(out.buf == expected.buf, "EncodePasswordAlgo falls back to the Unknown variant when p is empty");
}

void TestEncodeAccountPasswordNoPassword() {
    shuzagram::domain::PasswordSettings settings;
    settings.has_password = false;
    settings.secure_random = {0xAA, 0xBB};
    settings.new_algo.salt1 = {1};
    settings.new_algo.salt2 = {2};
    settings.new_algo.g = 3;
    settings.new_algo.p = {4};

    AccountPassword resp;
    resp.settings = settings;
    TLBuffer out;
    resp.Encode(out);

    TLBuffer expected;
    expected.PutID(0x957b50fb);
    expected.PutUint32(0); // flags: nothing set
    // new_algo
    EncodePasswordAlgo(expected, settings.new_algo);
    EncodeSecurePasswordAlgoUnknown(expected);
    PutTLBytes(expected, settings.secure_random);
    Check(out.buf == expected.buf, "AccountPassword (no password) omits current_algo/srp_B/srp_id/hint entirely");
}

void TestEncodeAccountPasswordWithPassword() {
    shuzagram::domain::PasswordSettings settings;
    settings.has_password = true;
    settings.has_recovery = true;
    settings.hint = "hi";
    settings.secure_random = {0xCC};
    settings.new_algo.p = {9};
    settings.new_algo.salt1 = {8};
    settings.new_algo.salt2 = {7};
    settings.new_algo.g = 3;
    settings.current_algo = settings.new_algo;
    settings.current_algo->salt1 = {1, 1};
    settings.srp_b = {0x11, 0x22};
    settings.srp_id = 42;

    AccountPassword resp;
    resp.settings = settings;
    TLBuffer out;
    resp.Encode(out);

    TLBuffer expected;
    expected.PutID(0x957b50fb);
    constexpr std::uint32_t kFlagHasRecovery = 1u << 0;
    constexpr std::uint32_t kFlagHasPassword = 1u << 2;
    constexpr std::uint32_t kFlagHint = 1u << 3;
    expected.PutUint32(kFlagHasRecovery | kFlagHasPassword | kFlagHint);
    EncodePasswordAlgo(expected, *settings.current_algo);
    PutTLBytes(expected, settings.srp_b);
    expected.PutLong(settings.srp_id);
    PutTLBytes(expected, std::vector<std::uint8_t>(settings.hint.begin(), settings.hint.end()));
    EncodePasswordAlgo(expected, settings.new_algo);
    EncodeSecurePasswordAlgoUnknown(expected);
    PutTLBytes(expected, settings.secure_random);
    Check(out.buf == expected.buf, "AccountPassword (has password) encodes current_algo/srp_B/srp_id/hint");
}

} // namespace

int main() {
    TestDecodeInputCheckPasswordEmpty();
    TestDecodeInputCheckPasswordSrp();
    TestEncodePasswordAlgoModPow();
    TestEncodePasswordAlgoUnknownWhenEmpty();
    TestEncodeAccountPasswordNoPassword();
    TestEncodeAccountPasswordWithPassword();
    if (g_failures == 0) {
        std::printf("all mtproto password message tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto password message test(s) failed\n", g_failures);
    return 1;
}
