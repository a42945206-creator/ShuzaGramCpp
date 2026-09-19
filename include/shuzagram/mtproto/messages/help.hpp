#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "shuzagram/mtproto/messages/bool.hpp"
#include "shuzagram/mtproto/tl_buffer.hpp"

// TL structs for help.getConfig. Field order, type ids, and every constant
// value below are copied directly from the ACTUAL running ShuzaGram Go
// server (internal/compat/tdesktop/config.go's BuildConfig, called by
// internal/rpc/help.go's onHelpGetConfig) -- not invented for this port.
// This is one of the first calls almost every real MTProto client makes
// (often the very first business RPC, immediately after invokeWithLayer
// unwrapping -- see NOTES/help-get-config-plan.md), so getting a real
// client to accept our response at all is the point of faithfully copying
// the Go source's exact numbers rather than picking plausible-looking
// ones.
namespace shuzagram::mtproto::messages {

inline constexpr std::uint32_t kHelpGetConfigRequestTypeId = 0xc4f9186b;

// help.getConfig#c4f9186b = Config; -- no fields.
struct HelpGetConfigRequest {
    static constexpr std::uint32_t kTypeId = kHelpGetConfigRequestTypeId;
    void DecodeBare(TLBuffer&) const {}
};

// dcOption#18b7a10d flags:# ipv6:flags.0?true ... id:int ip_address:string
//   port:int secret:flags.10?bytes = DcOption;
//
// Only the fields BuildConfig ever actually sets: no ipv6/media_only/cdn/
// static/secret -- this server is a single plain IPv4 backend.
struct DcOption {
    int id = 0;
    std::string ip_address;
    int port = 0;

    void Encode(TLBuffer& b) const {
        b.PutID(0x18b7a10d);
        b.PutUint32(0); // flags: no ipv6/media_only/tcpo_only/cdn/static/secret
        b.PutInt32(id);
        b.PutBytes({ip_address.begin(), ip_address.end()});
        b.PutInt32(port);
    }
};

// reactionEmoji#1b2286b8 emoticon:string = Reaction;
inline void EncodeReactionEmoji(TLBuffer& b, const std::string& emoticon) {
    b.PutID(0x1b2286b8);
    b.PutBytes({emoticon.begin(), emoticon.end()});
}

// config#cc1a241e -- see BuildConfig in the Go source for where every one
// of these numbers comes from; NOT arbitrary placeholders. Fields this
// project has no equivalent config concept for yet (me_url_prefix,
// autoupdate_url_prefix, suggested_lang_code/lang_pack versions,
// autologin_token, gif/venue/img search usernames beyond the one BuildConfig
// itself hardcodes, static_maps_provider, tmp_sessions) are left at their
// Go zero-value/unset state, exactly like BuildConfig's own struct literal
// leaves them.
struct Config {
    int dc = 1;              // this deployment is single-backend -- DC 1 is the only one, always
    std::string ip_address;  // the server's own advertised address
    int port = 0;
    std::int64_t date = 0;
    std::int64_t expires = 0; // date + 1 hour, matching BuildConfig

    void Encode(TLBuffer& b) const {
        constexpr std::uint32_t kFlagRevokePmInbox = 1u << 6;
        constexpr std::uint32_t kFlagGifSearchUsername = 1u << 9;
        constexpr std::uint32_t kFlagReactionsDefault = 1u << 15;
        const std::uint32_t flags = kFlagRevokePmInbox | kFlagGifSearchUsername | kFlagReactionsDefault;

        b.PutID(0xcc1a241e);
        b.PutUint32(flags);
        b.PutInt32(static_cast<std::int32_t>(date));
        b.PutInt32(static_cast<std::int32_t>(expires));
        EncodeBool(b, false); // test_mode
        b.PutInt32(dc);       // this_dc

        DcOption opt;
        opt.id = dc;
        opt.ip_address = ip_address;
        opt.port = port;
        b.PutVectorHeader(1);
        opt.Encode(b);

        b.PutBytes({}); // dc_txt_domain_name: unset, matching BuildConfig
        b.PutInt32(200);      // chat_size_max
        b.PutInt32(200000);   // megagroup_size_max
        b.PutInt32(100);      // forwarded_count_max
        b.PutInt32(120000);   // online_update_period_ms
        b.PutInt32(5000);     // offline_blur_timeout_ms
        b.PutInt32(30000);    // offline_idle_timeout_ms
        b.PutInt32(300000);   // online_cloud_timeout_ms
        b.PutInt32(30000);    // notify_cloud_delay_ms
        b.PutInt32(1500);     // notify_default_delay_ms
        b.PutInt32(60000);    // push_chat_period_ms
        b.PutInt32(2);        // push_chat_limit
        b.PutInt32(172800);   // edit_time_limit
        b.PutInt32(2147483647); // revoke_time_limit
        b.PutInt32(2147483647); // revoke_pm_time_limit
        b.PutInt32(2419200);   // rating_e_decay
        b.PutInt32(200);       // stickers_recent_limit
        b.PutInt32(0);         // channels_read_media_period (unset in BuildConfig)
        // tmp_sessions (flag bit 0): unset.
        b.PutInt32(20000); // call_receive_timeout_ms
        b.PutInt32(90000); // call_ring_timeout_ms
        b.PutInt32(30000); // call_connect_timeout_ms
        b.PutInt32(10000); // call_packet_timeout_ms
        b.PutBytes({});    // me_url_prefix (unset -- no public web-preview links concept in this port)
        // autoupdate_url_prefix (bit 7): unset.
        b.PutBytes(std::vector<std::uint8_t>{'g', 'i', 'f'}); // gif_search_username (bit 9)
        // venue_search_username (bit 10), img_search_username (bit 11),
        // static_maps_provider (bit 12): unset.
        b.PutInt32(1024); // caption_length_max
        b.PutInt32(4096); // message_length_max
        b.PutInt32(dc);   // webfile_dc_id
        // suggested_lang_code / lang_pack_version / base_lang_pack_version (bit 2): unset.
        EncodeReactionEmoji(b, "\xF0\x9F\x91\x8D"); // reactions_default (bit 15): U+1F44D "👍"
        // autologin_token (bit 16): unset.
    }
};

} // namespace shuzagram::mtproto::messages
