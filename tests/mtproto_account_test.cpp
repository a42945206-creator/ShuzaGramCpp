// Wire-format checks for account.updateStatus/account.getAuthorizations
// (messages/account.hpp) and the new bare-Bool decoder (messages/bool.hpp),
// same discipline as the other mtproto_*_test.cpp files: exact constructor
// ids, copied from gotd/td (tg/tl_{account_update_status,
// account_get_authorizations,account_authorizations,authorization}_gen.go),
// not invented.

#include <cstdio>
#include <string>

#include "shuzagram/mtproto/messages/account.hpp"

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

std::string DecodeTLString(TLBuffer& b) {
    const auto v = b.GetBytes();
    return {v.begin(), v.end()};
}

void TestDecodeBoolRoundTrip() {
    TLBuffer b;
    EncodeBool(b, true);
    EncodeBool(b, false);
    Check(DecodeBool(b) == true, "boolTrue decodes to true");
    Check(DecodeBool(b) == false, "boolFalse decodes to false");
    Check(b.buf.empty(), "no leftover bytes");
}

void TestDecodeBoolRejectsUnknownId() {
    TLBuffer b;
    b.PutID(0xdeadbeef);
    bool threw = false;
    try {
        DecodeBool(b);
    } catch (const UnexpectedIdError&) {
        threw = true;
    }
    Check(threw, "an id that's neither boolTrue nor boolFalse throws UnexpectedIdError");
}

void TestDecodeAccountUpdateStatusRequest() {
    {
        TLBuffer b;
        EncodeBool(b, true);
        AccountUpdateStatusRequest req;
        req.DecodeBare(b);
        Check(req.offline == true, "offline=true decodes correctly");
        Check(b.buf.empty(), "no leftover bytes");
    }
    {
        TLBuffer b;
        EncodeBool(b, false);
        AccountUpdateStatusRequest req;
        req.DecodeBare(b);
        Check(req.offline == false, "offline=false decodes correctly");
    }
}

void TestDecodeAccountGetAuthorizationsRequestHasNoFields() {
    TLBuffer b; // empty -- the real request carries nothing at all
    AccountGetAuthorizationsRequest req;
    req.DecodeBare(b);
    Check(b.buf.empty(), "AccountGetAuthorizationsRequest::DecodeBare consumes nothing");
}

void TestEncodeAuthorizationCurrentAndOfficialAppFlags() {
    shuzagram::domain::Authorization a;
    a.hash = 42;
    a.device_model = "PC";
    a.platform = "desktop";
    a.system_version = "Linux";
    a.api_id = 6;
    a.app_version = "1.0";
    a.ip = "203.0.113.7";

    TLBuffer b;
    EncodeAuthorization(b, a, /*current=*/true, /*now=*/1000);

    Check(b.PeekID() == 0xad01d61d, "encodes with the real authorization#ad01d61d type id");
    b.ConsumeID(0xad01d61d);
    const std::uint32_t flags = b.Uint32();
    Check((flags & (1u << 0)) != 0, "current flag set when current=true");
    Check((flags & (1u << 1)) != 0, "official_app flag is always set (matches tgAuthorization)");
    Check((flags & (1u << 2)) == 0, "password_pending is never set (tgAuthorization never sets it either)");

    Check(b.Long() == 42, "hash encoded");
    Check(DecodeTLString(b) == "PC", "device_model encoded verbatim (no branding rewrite)");
    Check(DecodeTLString(b) == "desktop", "platform encoded verbatim");
    Check(DecodeTLString(b) == "Linux", "system_version encoded verbatim");
    Check(b.Int32() == 6, "api_id encoded");
    Check(DecodeTLString(b).empty(), "app_name is empty (no branding-config app-name mapping ported)");
    Check(DecodeTLString(b) == "1.0", "app_version encoded verbatim");
    Check(b.Int32() == 1000, "date_created falls back to now when created_at was never set");
    Check(b.Int32() == 1000, "date_active falls back to date_created when active_at was never set");
    Check(DecodeTLString(b) == "203.0.113.7", "ip encoded");
    Check(DecodeTLString(b) == "Unknown", "country is hardcoded Unknown, matching tgAuthorization");
    Check(DecodeTLString(b) == "Unknown", "region is hardcoded Unknown");
    Check(b.buf.empty(), "no leftover bytes");
}

void TestEncodeAuthorizationNotCurrent() {
    shuzagram::domain::Authorization a;
    TLBuffer b;
    EncodeAuthorization(b, a, /*current=*/false, /*now=*/1000);
    b.ConsumeID(0xad01d61d);
    const std::uint32_t flags = b.Uint32();
    Check((flags & (1u << 0)) == 0, "current flag unset when current=false");
}

void TestEncodeAccountAuthorizations() {
    shuzagram::domain::Authorization mine;
    mine.auth_key_id = {1, 2, 3, 4, 5, 6, 7, 8};
    shuzagram::domain::Authorization other;
    other.auth_key_id = {9, 9, 9, 9, 9, 9, 9, 9};

    TLBuffer b;
    EncodeAccountAuthorizations(b, {mine, other}, mine.auth_key_id, 500);

    Check(b.PeekID() == 0x4bff8ea0, "encodes with the real account.authorizations#4bff8ea0 type id");
    b.ConsumeID(0x4bff8ea0);
    Check(b.Int32() == 0, "authorization_ttl_days is always 0 (matches the Go source's own stub setter)");
    Check(b.VectorHeader() == 2, "both authorizations are encoded");

    Check(b.PeekID() == 0xad01d61d, "first entry is a real authorization#ad01d61d");
    b.ConsumeID(0xad01d61d);
    Check((b.Uint32() & 1u) != 0, "the entry matching current_auth_key_id has the current flag set");
    // Skip the rest of the first entry's fields.
    b.Long();                 // hash
    DecodeTLString(b);        // device_model
    DecodeTLString(b);        // platform
    DecodeTLString(b);        // system_version
    b.Int32();                // api_id
    DecodeTLString(b);        // app_name
    DecodeTLString(b);        // app_version
    b.Int32();                // date_created
    b.Int32();                // date_active
    DecodeTLString(b);        // ip
    DecodeTLString(b);        // country
    DecodeTLString(b);        // region

    b.ConsumeID(0xad01d61d);
    Check((b.Uint32() & 1u) == 0, "the non-matching entry does not have the current flag set");
}

void TestDecodeAccountUpdateProfileRequest() {
    {
        // No flags set -- every field left unset (client is only updating,
        // say, an emoji status via a different call and sent this bare).
        TLBuffer b;
        b.PutUint32(0);
        AccountUpdateProfileRequest req;
        req.DecodeBare(b);
        Check(!req.update.has_first_name, "no flags -> has_first_name is false");
        Check(!req.update.has_last_name, "no flags -> has_last_name is false");
        Check(!req.update.has_about, "no flags -> has_about is false");
        Check(b.buf.empty(), "no leftover bytes");
    }
    {
        // Only about set (bit 2) -- first/last name must stay unset.
        TLBuffer b;
        b.PutUint32(1u << 2);
        b.PutBytes(std::vector<std::uint8_t>{'h', 'i'});
        AccountUpdateProfileRequest req;
        req.DecodeBare(b);
        Check(!req.update.has_first_name, "bit 2 only -> has_first_name stays false");
        Check(!req.update.has_last_name, "bit 2 only -> has_last_name stays false");
        Check(req.update.has_about && req.update.about == "hi", "bit 2 decodes about");
    }
    {
        // All three set, in wire order (first_name, last_name, about).
        TLBuffer b;
        b.PutUint32((1u << 0) | (1u << 1) | (1u << 2));
        b.PutBytes(std::vector<std::uint8_t>{'A'});
        b.PutBytes(std::vector<std::uint8_t>{'B'});
        b.PutBytes(std::vector<std::uint8_t>{'C'});
        AccountUpdateProfileRequest req;
        req.DecodeBare(b);
        Check(req.update.has_first_name && req.update.first_name == "A", "first_name decoded first");
        Check(req.update.has_last_name && req.update.last_name == "B", "last_name decoded second");
        Check(req.update.has_about && req.update.about == "C", "about decoded third");
        Check(b.buf.empty(), "no leftover bytes");
    }
}

void TestDecodeAccountCheckUsernameRequest() {
    TLBuffer b;
    b.PutBytes(std::vector<std::uint8_t>{'a', 'l', 'i', 'c', 'e'});
    AccountCheckUsernameRequest req;
    req.DecodeBare(b);
    Check(req.username == "alice", "username decoded");
    Check(b.buf.empty(), "no leftover bytes");
}

void TestDecodeAccountUpdateUsernameRequest() {
    TLBuffer b;
    b.PutBytes(std::vector<std::uint8_t>{});
    AccountUpdateUsernameRequest req;
    req.DecodeBare(b);
    Check(req.username.empty(), "an empty string decodes correctly (clears the username)");
}

void TestDecodeBirthdayWithoutYear() {
    TLBuffer b;
    b.PutUint32(0); // no year flag
    b.PutInt32(15);
    b.PutInt32(6);
    const auto birthday = DecodeBirthday(b);
    Check(birthday.day == 15, "day decoded");
    Check(birthday.month == 6, "month decoded");
    Check(birthday.year == 0, "year stays 0 when its flag is unset");
    Check(b.buf.empty(), "no leftover bytes");
}

void TestDecodeBirthdayWithYear() {
    TLBuffer b;
    b.PutUint32(1u << 0);
    b.PutInt32(15);
    b.PutInt32(6);
    b.PutInt32(1990);
    const auto birthday = DecodeBirthday(b);
    Check(birthday.year == 1990, "year decoded when its flag is set");
}

void TestDecodeAccountUpdateBirthdayRequest() {
    {
        // Flag bit 0 unset -- absent birthday, must decode to the clearing
        // zero value, not leave the field uninitialized.
        TLBuffer b;
        b.PutUint32(0);
        AccountUpdateBirthdayRequest req;
        req.DecodeBare(b);
        Check(!req.birthday.IsSet(), "an absent birthday decodes to the zero (clearing) value");
        Check(b.buf.empty(), "no leftover bytes");
    }
    {
        TLBuffer b;
        b.PutUint32(1u << 0);
        b.PutUint32(0); // nested Birthday's own flags: no year
        b.PutInt32(1);
        b.PutInt32(1);
        AccountUpdateBirthdayRequest req;
        req.DecodeBare(b);
        Check(req.birthday.day == 1 && req.birthday.month == 1, "a present birthday is decoded");
        Check(b.buf.empty(), "no leftover bytes");
    }
}

} // namespace

int main() {
    TestDecodeBoolRoundTrip();
    TestDecodeBoolRejectsUnknownId();
    TestDecodeAccountUpdateStatusRequest();
    TestDecodeAccountGetAuthorizationsRequestHasNoFields();
    TestDecodeAccountUpdateProfileRequest();
    TestDecodeAccountCheckUsernameRequest();
    TestDecodeAccountUpdateUsernameRequest();
    TestDecodeBirthdayWithoutYear();
    TestDecodeBirthdayWithYear();
    TestDecodeAccountUpdateBirthdayRequest();
    TestEncodeAuthorizationCurrentAndOfficialAppFlags();
    TestEncodeAuthorizationNotCurrent();
    TestEncodeAccountAuthorizations();
    if (g_failures == 0) {
        std::printf("all mtproto account tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto account test(s) failed\n", g_failures);
    return 1;
}
