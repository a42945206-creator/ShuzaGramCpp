// Wire-format checks for users.getUsers's request/response (messages/users.hpp),
// same discipline as mtproto_help_config_test.cpp: decode field-by-field and
// check every constructor id/flag bit against the real gotd/td-generated wire
// format (github.com/iamxvbaba/td, tg/tl_{user,input_user,users_get_users,...}
// _gen.go) -- not this port's own invented layout.

#include <cstdio>
#include <string>

#include "shuzagram/mtproto/messages/users.hpp"

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

void TestDecodeInputUserVariants() {
    {
        TLBuffer b;
        b.PutID(0xb98886cf); // inputUserEmpty
        auto in = InputUser::Decode(b);
        Check(in.kind == InputUser::Kind::Empty, "inputUserEmpty decodes to Kind::Empty");
        Check(b.buf.empty(), "inputUserEmpty carries no fields");
    }
    {
        TLBuffer b;
        b.PutID(0xf7c1b13f); // inputUserSelf
        auto in = InputUser::Decode(b);
        Check(in.kind == InputUser::Kind::SelfUser, "inputUserSelf decodes to Kind::SelfUser");
        Check(b.buf.empty(), "inputUserSelf carries no fields");
    }
    {
        TLBuffer b;
        b.PutID(0xf21158c6); // inputUser
        b.PutLong(123456);
        b.PutLong(999);
        auto in = InputUser::Decode(b);
        Check(in.kind == InputUser::Kind::ById, "inputUser decodes to Kind::ById");
        Check(in.user_id == 123456, "inputUser.user_id decoded");
        Check(in.access_hash == 999, "inputUser.access_hash decoded");
    }
    {
        TLBuffer b;
        b.PutID(0x1da448e2); // inputUserFromMessage
        bool threw = false;
        try {
            InputUser::Decode(b);
        } catch (const shuzagram::domain::NotImplementedError&) {
            threw = true;
        }
        Check(threw, "inputUserFromMessage throws NotImplementedError instead of misparsing");
    }
}

void TestDecodeUsersGetUsersRequest() {
    TLBuffer b;
    b.PutVectorHeader(2);
    b.PutID(0xf7c1b13f); // self
    b.PutID(0xf21158c6); // by id
    b.PutLong(7);
    b.PutLong(0);

    UsersGetUsersRequest req;
    req.DecodeBare(b);
    Check(req.ids.size() == 2, "decodes both vector entries");
    Check(req.ids[0].kind == InputUser::Kind::SelfUser, "first entry is self");
    Check(req.ids[1].kind == InputUser::Kind::ById && req.ids[1].user_id == 7, "second entry is inputUser(7)");
    Check(b.buf.empty(), "no leftover bytes after the vector");
}

void TestEncodeMinimalUser() {
    shuzagram::domain::User u;
    u.id = 42;
    u.first_name = "Ada";

    TLBuffer b;
    EncodeUser(b, u, /*is_self=*/false, /*now=*/1000);

    Check(b.PeekID() == 0xb1b8cc83, "encodes with the real user#b1b8cc83 type id");
    b.ConsumeID(0xb1b8cc83);
    const std::uint32_t flags = b.Uint32();
    const std::uint32_t flags2 = b.Uint32();
    Check((flags & (1u << 10)) == 0, "self flag unset when is_self=false");
    Check((flags & (1u << 1)) != 0, "first_name flag set");
    Check((flags & (1u << 5)) != 0, "photo flag always set (empty variant when no photo)");
    Check((flags & (1u << 6)) != 0, "status flag set for a non-bot user");
    Check(flags2 == 0, "no flags2 bits for a minimal user");

    Check(b.Long() == 42, "id encoded");
    Check(DecodeTLString(b) == "Ada", "first_name encoded");
    Check(b.PeekID() == 0x4f11bae1, "no photo -> userProfilePhotoEmpty");
    b.ConsumeID(0x4f11bae1);
    Check(b.PeekID() == 0x7b197dc8, "default/unknown status projects as userStatusRecently");
    b.ConsumeID(0x7b197dc8);
    Check(b.Uint32() == 0, "userStatusRecently flags are 0 (by_me never set by this port)");
    Check(b.buf.empty(), "no leftover bytes for a minimal user");
}

void TestEncodeSelfSetsSelfFlag() {
    shuzagram::domain::User u;
    u.id = 1;
    TLBuffer b;
    EncodeUser(b, u, /*is_self=*/true, /*now=*/1000);
    b.ConsumeID(0xb1b8cc83);
    const std::uint32_t flags = b.Uint32();
    Check((flags & (1u << 10)) != 0, "self flag set when is_self=true");
}

void TestEncodeBotOmitsPhoneAndStatusButHasVersion() {
    shuzagram::domain::User u;
    u.id = 5;
    u.bot = true;
    u.bot_info_version = 3;
    u.phone = "15550001111"; // must NOT be encoded for a bot

    TLBuffer b;
    EncodeUser(b, u, false, 1000);
    b.ConsumeID(0xb1b8cc83);
    const std::uint32_t flags = b.Uint32();
    const std::uint32_t flags2 = b.Uint32();
    Check((flags & (1u << 14)) != 0, "bot flag set (doubles as bot_info_version presence)");
    Check((flags & (1u << 4)) == 0, "phone flag unset for a bot even though domain.phone is non-empty");
    Check((flags & (1u << 6)) == 0, "status flag unset for a bot (no presence, matches applyTgUserBotFields)");
    Check((flags2 & (1u << 11)) != 0, "bot_business flag2 set (no system-user exemption ported)");

    Check(b.Long() == 5, "id encoded");
    Check(b.PeekID() == 0x4f11bae1, "no photo");
    b.ConsumeID(0x4f11bae1);
    Check(b.Int32() == 3, "bot_info_version encoded");
    Check(b.buf.empty(), "no leftover bytes for a minimal bot user");
}

void TestEncodeDeletedUserOmitsEverythingButId() {
    shuzagram::domain::User u;
    u.id = 9;
    u.access_hash = 555; // must NOT be encoded either, matching Go's tgUser deleted branch
    u.deleted = true;
    u.first_name = "Ghost";

    TLBuffer b;
    EncodeUser(b, u, false, 1000);
    Check(b.PeekID() == 0xb1b8cc83, "still the same user# constructor");
    b.ConsumeID(0xb1b8cc83);
    const std::uint32_t flags = b.Uint32();
    const std::uint32_t flags2 = b.Uint32();
    Check(flags == (1u << 13), "only the deleted flag is set");
    Check(flags2 == 0, "flags2 is empty (frozen mark not ported)");
    Check(b.Long() == 9, "id encoded");
    Check(b.buf.empty(), "no access_hash/first_name/etc for a deleted user");
}

void TestEncodeRestrictionReasonDropsIncompleteEntries() {
    shuzagram::domain::User u;
    u.id = 1;
    u.restriction_reasons = {
        {"ios", "spam", "Spam account"},
        {"", "spam", "missing platform, must be dropped"},
    };

    TLBuffer b;
    EncodeUser(b, u, false, 1000);
    b.ConsumeID(0xb1b8cc83);
    const std::uint32_t flags = b.Uint32();
    b.Uint32(); // flags2
    Check((flags & (1u << 18)) != 0, "restricted flag set (one valid reason survives)");
    b.Long(); // id
    b.ConsumeID(0x4f11bae1); // photo
    b.ConsumeID(0x7b197dc8); // status
    b.Uint32(); // status flags
    Check(b.VectorHeader() == 1, "only the complete reason is encoded");
    Check(b.PeekID() == 0xd072acb4, "restrictionReason#d072acb4");
}

} // namespace

int main() {
    TestDecodeInputUserVariants();
    TestDecodeUsersGetUsersRequest();
    TestEncodeMinimalUser();
    TestEncodeSelfSetsSelfFlag();
    TestEncodeBotOmitsPhoneAndStatusButHasVersion();
    TestEncodeDeletedUserOmitsEverythingButId();
    TestEncodeRestrictionReasonDropsIncompleteEntries();
    if (g_failures == 0) {
        std::printf("all mtproto users tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto users test(s) failed\n", g_failures);
    return 1;
}
