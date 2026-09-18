// Wire-format checks for the auth.sendCode/auth.signIn/auth.signUp TL
// structs (messages/auth.hpp). These are hand-written against
// /tmp/td-src's generated code (not themselves generated), so this test
// round-trips every request decoder against a manually-built buffer (the
// kind of buffer a real client's Encode would produce) and checks every
// response encoder byte-for-byte against a manually-assembled expected
// buffer -- the same "compute the expected bytes independently, don't just
// decode-what-we-encoded" discipline used for the handshake messages.

#include <cstdio>
#include <cstring>
#include <string>

#include "shuzagram/mtproto/messages/auth.hpp"

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

// TL string/bytes encoding: 1-byte length prefix (short form) + data,
// padded to a multiple of 4 -- written by hand here rather than reusing
// TLBuffer::PutBytes, so the test doesn't just check the code against
// itself.
void PutTLString(TLBuffer& b, const std::string& s) {
    Check(s.size() <= 253, "PutTLString test helper only supports the short form");
    b.buf.push_back(static_cast<std::uint8_t>(s.size()));
    b.buf.insert(b.buf.end(), s.begin(), s.end());
    std::size_t total = 1 + s.size();
    while (total % 4 != 0) {
        b.buf.push_back(0);
        ++total;
    }
}

void TestDecodeAuthSendCodeRequest() {
    TLBuffer b;
    PutTLString(b, "+15551234567");
    b.PutInt32(12345); // api_id
    PutTLString(b, "somehash");
    // codeSettings#ad253d78 flags:# = CodeSettings, flags=0 (no optional fields)
    b.PutUint32(0);

    AuthSendCodeRequest req;
    req.DecodeBare(b);
    Check(req.phone_number == "+15551234567", "AuthSendCodeRequest decodes phone_number");
    Check(req.api_id == 12345, "AuthSendCodeRequest decodes api_id");
    Check(req.api_hash == "somehash", "AuthSendCodeRequest decodes api_hash");
    Check(b.buf.empty(), "AuthSendCodeRequest.DecodeBare consumes exactly its own fields");
}

void TestDecodeCodeSettingsWithLogoutTokensAndToken() {
    TLBuffer b;
    // flags: bit 6 (logout_tokens) | bit 8 (token, which also gates app_sandbox)
    b.PutUint32((1u << 6) | (1u << 8));
    b.PutVectorHeader(2);
    PutTLString(b, "tok1");
    PutTLString(b, "tok2longer");
    PutTLString(b, "pushtoken");
    // app_sandbox: a bare TL Bool is just a 4-byte constructor id.
    b.PutID(0x997275b5); // boolTrue

    CodeSettings settings;
    settings.DecodeBare(b);
    Check(b.buf.empty(), "CodeSettings.DecodeBare with logout_tokens+token+app_sandbox consumes exactly its fields");
}

void TestDecodeAuthSignInRequestWithCode() {
    TLBuffer b;
    b.PutUint32(1u << 0); // flags: phone_code present, no email_verification
    PutTLString(b, "+15551234567");
    PutTLString(b, "somehash");
    PutTLString(b, "12345");

    AuthSignInRequest req;
    req.DecodeBare(b);
    Check(req.phone_number == "+15551234567", "AuthSignInRequest decodes phone_number");
    Check(req.phone_code_hash == "somehash", "AuthSignInRequest decodes phone_code_hash");
    Check(req.phone_code == "12345", "AuthSignInRequest decodes phone_code");
    Check(b.buf.empty(), "AuthSignInRequest.DecodeBare consumes exactly its own fields");
}

void TestDecodeAuthSignInRequestWithEmailVerificationThrows() {
    TLBuffer b;
    b.PutUint32((1u << 0) | (1u << 1)); // phone_code AND email_verification
    PutTLString(b, "+15551234567");
    PutTLString(b, "somehash");
    PutTLString(b, "12345");
    // (deliberately no email_verification bytes -- DecodeBare must throw
    // before trying to read them)

    AuthSignInRequest req;
    try {
        req.DecodeBare(b);
        Check(false, "email_verification should throw NotImplementedError");
    } catch (const shuzagram::domain::NotImplementedError&) {
        Check(true, "email_verification throws NotImplementedError rather than misparsing");
    }
}

void TestDecodeAuthSignUpRequest() {
    TLBuffer b;
    b.PutUint32(0); // flags: no_joined_notifications not set
    PutTLString(b, "+15551234567");
    PutTLString(b, "somehash");
    PutTLString(b, "Ada");
    PutTLString(b, "Lovelace");

    AuthSignUpRequest req;
    req.DecodeBare(b);
    Check(req.phone_number == "+15551234567", "AuthSignUpRequest decodes phone_number");
    Check(req.phone_code_hash == "somehash", "AuthSignUpRequest decodes phone_code_hash");
    Check(req.first_name == "Ada" && req.last_name == "Lovelace", "AuthSignUpRequest decodes first/last name");
    Check(b.buf.empty(), "AuthSignUpRequest.DecodeBare consumes exactly its own fields");
}

void TestEncodeAuthSentCode() {
    AuthSentCode resp;
    resp.code_length = 5;
    resp.phone_code_hash = "abc";
    TLBuffer out;
    resp.Encode(out);

    TLBuffer expected;
    expected.PutID(0x5e002502); // auth.sentCode
    expected.PutUint32(0);      // flags
    expected.PutID(0x3dbb5986); // authSentCodeTypeApp
    expected.PutInt32(5);
    PutTLString(expected, "abc");

    Check(out.buf == expected.buf, "AuthSentCode encodes to the hand-assembled expected bytes");
}

void TestEncodeAuthAuthorizationMinimalUser() {
    shuzagram::domain::User user;
    user.id = 42;
    user.access_hash = 777;
    user.first_name = "Ada";
    // last_name and phone deliberately left empty to check their flag bits
    // are correctly NOT set.

    AuthAuthorization resp;
    resp.user = user;
    TLBuffer out;
    resp.Encode(out);

    TLBuffer expected;
    expected.PutID(0x2ea2c0d4); // auth.authorization
    expected.PutUint32(0);      // flags
    expected.PutID(0xb1b8cc83); // user
    constexpr std::uint32_t kSelf = 1u << 10;
    constexpr std::uint32_t kAccessHash = 1u << 0;
    constexpr std::uint32_t kFirstName = 1u << 1;
    expected.PutUint32(kSelf | kAccessHash | kFirstName);
    expected.PutUint32(0); // flags2
    expected.PutLong(42);
    expected.PutLong(777);
    PutTLString(expected, "Ada");

    Check(out.buf == expected.buf, "AuthAuthorization encodes a minimal self-user to the expected bytes");
}

void TestEncodeAuthAuthorizationSignUpRequired() {
    AuthAuthorizationSignUpRequired resp;
    TLBuffer out;
    resp.Encode(out);

    TLBuffer expected;
    expected.PutID(0x44747e9a);
    expected.PutUint32(0);
    Check(out.buf == expected.buf, "AuthAuthorizationSignUpRequired encodes to id+zero-flags only");
}

} // namespace

int main() {
    TestDecodeAuthSendCodeRequest();
    TestDecodeCodeSettingsWithLogoutTokensAndToken();
    TestDecodeAuthSignInRequestWithCode();
    TestDecodeAuthSignInRequestWithEmailVerificationThrows();
    TestDecodeAuthSignUpRequest();
    TestEncodeAuthSentCode();
    TestEncodeAuthAuthorizationMinimalUser();
    TestEncodeAuthAuthorizationSignUpRequired();
    if (g_failures == 0) {
        std::printf("all mtproto auth message tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto auth message test(s) failed\n", g_failures);
    return 1;
}
