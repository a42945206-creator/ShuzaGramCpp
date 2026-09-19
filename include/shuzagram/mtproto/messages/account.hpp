#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "shuzagram/domain/authorization.hpp"
#include "shuzagram/domain/user.hpp"
#include "shuzagram/mtproto/messages/bool.hpp"
#include "shuzagram/mtproto/tl_buffer.hpp"

// account.updateStatus#6628562c offline:Bool = Bool;
// account.getAuthorizations#e320c158 = account.Authorizations;
// account.authorizations#4bff8ea0 authorization_ttl_days:int
//   authorizations:Vector<Authorization> = account.Authorizations;
// authorization#ad01d61d flags:# current:flags.0?true official_app:flags.1?true
//   password_pending:flags.2?true encrypted_requests_disabled:flags.3?true
//   call_requests_disabled:flags.4?true unconfirmed:flags.5?true hash:long
//   device_model:string platform:string system_version:string api_id:int
//   app_name:string app_version:string date_created:int date_active:int
//   ip:string country:string region:string = Authorization;
// account.updateProfile#78515775 flags:# first_name:flags.0?string
//   last_name:flags.1?string about:flags.2?string = User;
//
// Constructor ids copied from gotd/td (github.com/iamxvbaba/td@v1.3.3,
// tg/tl_{account_update_status,account_get_authorizations,
// account_authorizations,authorization,account_update_profile}_gen.go),
// same as every other messages/ header in this project.
namespace shuzagram::mtproto::messages {

struct AccountUpdateStatusRequest {
    static constexpr std::uint32_t kTypeId = 0x6628562c;
    bool offline = false;

    void DecodeBare(TLBuffer& b) { offline = DecodeBool(b); }
};

// account.getAuthorizations#e320c158 -- no fields.
struct AccountGetAuthorizationsRequest {
    static constexpr std::uint32_t kTypeId = 0xe320c158;
    void DecodeBare(TLBuffer&) const {}
};

// account.updateProfile#78515775 flags:# first_name:flags.0?string
//   last_name:flags.1?string about:flags.2?string = User;
//
// Each field is independently optional -- absence means "leave unchanged",
// not "clear it". The partial-update MERGE itself happens in
// users::UpdateProfile (include/shuzagram/users/update_profile.hpp), not
// here; this struct only carries what the wire actually said.
struct AccountUpdateProfileRequest {
    static constexpr std::uint32_t kTypeId = 0x78515775;
    domain::UserProfileUpdate update;

    void DecodeBare(TLBuffer& b) {
        constexpr std::uint32_t kFlagFirstName = 1u << 0;
        constexpr std::uint32_t kFlagLastName = 1u << 1;
        constexpr std::uint32_t kFlagAbout = 1u << 2;

        const std::uint32_t flags = b.Uint32();
        update = domain::UserProfileUpdate{};
        if (flags & kFlagFirstName) {
            const auto v = b.GetBytes();
            update.first_name.assign(v.begin(), v.end());
            update.has_first_name = true;
        }
        if (flags & kFlagLastName) {
            const auto v = b.GetBytes();
            update.last_name.assign(v.begin(), v.end());
            update.has_last_name = true;
        }
        if (flags & kFlagAbout) {
            const auto v = b.GetBytes();
            update.about.assign(v.begin(), v.end());
            update.has_about = true;
        }
    }
};

// authorization#ad01d61d. Mirrors the real Go projection (tgAuthorization,
// internal/rpc/account.go) exactly for the fields it sets: only current/
// official_app (always true) ever get their flag bits -- password_pending/
// encrypted_requests_disabled/call_requests_disabled/unconfirmed are never
// set by that function either, so this port leaves them unset too, not
// invented gaps.
//
// One deliberate simplification beyond that: the real projection also runs
// device_model/platform/system_version/app_version/app_name through a
// branding layer (internal/branding -- rewrites "Telegram"/official hosts
// to the deployment's own product name, and derives app_name from the
// platform token). This port has no such branding-config subsystem, so
// those fields are encoded verbatim from the stored domain::Authorization,
// and app_name is always empty. See NOTES/account-get-authorizations-plan.md.
inline void EncodeAuthorization(TLBuffer& b, const domain::Authorization& a, bool current, std::int64_t now) {
    constexpr std::uint32_t kFlagCurrent = 1u << 0;
    constexpr std::uint32_t kFlagOfficialApp = 1u << 1;
    const std::uint32_t flags = (current ? kFlagCurrent : 0u) | kFlagOfficialApp;

    // Matches tgAuthorization's own fallback: a never-set timestamp must not
    // be encoded as the 1970 epoch.
    auto created = std::chrono::duration_cast<std::chrono::seconds>(a.created_at.time_since_epoch()).count();
    if (created == 0) created = now;
    auto active = std::chrono::duration_cast<std::chrono::seconds>(a.active_at.time_since_epoch()).count();
    if (active == 0) active = created;

    b.PutID(0xad01d61d);
    b.PutUint32(flags);
    b.PutLong(a.hash);
    b.PutBytes({a.device_model.begin(), a.device_model.end()});
    b.PutBytes({a.platform.begin(), a.platform.end()});
    b.PutBytes({a.system_version.begin(), a.system_version.end()});
    b.PutInt32(a.api_id);
    b.PutBytes({}); // app_name: no branding-config app-name mapping ported yet
    b.PutBytes({a.app_version.begin(), a.app_version.end()});
    b.PutInt32(static_cast<std::int32_t>(created));
    b.PutInt32(static_cast<std::int32_t>(active));
    b.PutBytes({a.ip.begin(), a.ip.end()});
    b.PutBytes(std::vector<std::uint8_t>{'U', 'n', 'k', 'n', 'o', 'w', 'n'}); // country
    b.PutBytes(std::vector<std::uint8_t>{'U', 'n', 'k', 'n', 'o', 'w', 'n'}); // region
}

// account.authorizations#4bff8ea0. authorization_ttl_days is always 0: the
// real Go source's own account.setAuthorizationTTL is itself an
// accept-and-discard stub (internal/rpc/account.go), so onAccountGetAuthorizations
// never sets a non-zero value either -- not a gap this port introduced.
inline void EncodeAccountAuthorizations(TLBuffer& b, const std::vector<domain::Authorization>& list,
                                          const std::array<std::uint8_t, 8>& current_auth_key_id,
                                          std::int64_t now) {
    b.PutID(0x4bff8ea0);
    b.PutInt32(0); // authorization_ttl_days
    b.PutVectorHeader(static_cast<std::int32_t>(list.size()));
    for (const auto& a : list) {
        EncodeAuthorization(b, a, a.auth_key_id == current_auth_key_id, now);
    }
}

} // namespace shuzagram::mtproto::messages
