// Wire-format checks for help.getConfig's response (messages/help.hpp),
// same discipline as mtproto_auth_messages_test.cpp: decode field-by-field
// and check every constant against the value ACTUALLY used by the live Go
// server's BuildConfig (internal/compat/tdesktop/config.go) -- these are
// not this port's own invented numbers, so the test asserts the exact
// upstream constant, not just "some int came back".

#include <cstdio>
#include <string>

#include "shuzagram/mtproto/messages/help.hpp"

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

void TestConfigEncodesGoSourceValues() {
    Config config;
    config.dc = 3;
    config.ip_address = "203.0.113.7";
    config.port = 2398;
    config.date = 1000;
    config.expires = 1000 + 3600;

    TLBuffer b;
    config.Encode(b);

    Check(b.PeekID() == 0xcc1a241e, "encodes with the real config#cc1a241e type id");
    b.ConsumeID(0xcc1a241e);

    const std::uint32_t flags = b.Uint32();
    Check((flags & (1u << 6)) != 0, "revoke_pm_inbox flag is set (BuildConfig sets it)");
    Check((flags & (1u << 9)) != 0, "gif_search_username flag is set");
    Check((flags & (1u << 15)) != 0, "reactions_default flag is set");

    Check(b.Int32() == 1000, "date matches the given time");
    Check(b.Int32() == 4600, "expires is date + 3600 (BuildConfig's now.Add(time.Hour))");
    const std::uint32_t test_mode_id = b.Uint32();
    Check(test_mode_id == 0xbc799737, "test_mode is boolFalse (BuildConfig: TestMode: false)");
    Check(b.Int32() == 3, "this_dc matches the given dc");

    Check(b.VectorHeader() == 1, "dc_options has exactly one entry (single-backend deployment)");
    Check(b.PeekID() == 0x18b7a10d, "the dc_options entry is a real dcOption#18b7a10d");
    b.ConsumeID(0x18b7a10d);
    Check(b.Uint32() == 0, "the dcOption has no flags set (plain IPv4, no cdn/static/secret/...)");
    Check(b.Int32() == 3, "dcOption.id matches this_dc");
    Check(DecodeTLString(b) == "203.0.113.7", "dcOption.ip_address matches the configured advertise address");
    Check(b.Int32() == 2398, "dcOption.port matches the configured port");

    Check(DecodeTLString(b).empty(), "dc_txt_domain_name is unset, matching BuildConfig");
    Check(b.Int32() == 200, "chat_size_max == 200 (BuildConfig)");
    Check(b.Int32() == 200000, "megagroup_size_max == 200000 (BuildConfig)");
    Check(b.Int32() == 100, "forwarded_count_max == 100 (BuildConfig)");
    Check(b.Int32() == 120000, "online_update_period_ms == 120000 (BuildConfig)");
    Check(b.Int32() == 5000, "offline_blur_timeout_ms == 5000 (BuildConfig)");
    Check(b.Int32() == 30000, "offline_idle_timeout_ms == 30000 (BuildConfig)");
    Check(b.Int32() == 300000, "online_cloud_timeout_ms == 300000 (BuildConfig)");
    Check(b.Int32() == 30000, "notify_cloud_delay_ms == 30000 (BuildConfig)");
    Check(b.Int32() == 1500, "notify_default_delay_ms == 1500 (BuildConfig)");
    Check(b.Int32() == 60000, "push_chat_period_ms == 60000 (BuildConfig)");
    Check(b.Int32() == 2, "push_chat_limit == 2 (BuildConfig)");
    Check(b.Int32() == 172800, "edit_time_limit == 172800 (BuildConfig)");
    Check(b.Int32() == 2147483647, "revoke_time_limit == INT32_MAX (BuildConfig)");
    Check(b.Int32() == 2147483647, "revoke_pm_time_limit == INT32_MAX (BuildConfig)");
    Check(b.Int32() == 2419200, "rating_e_decay == 2419200 (BuildConfig)");
    Check(b.Int32() == 200, "stickers_recent_limit == 200 (BuildConfig)");
    Check(b.Int32() == 0, "channels_read_media_period == 0 (unset in BuildConfig)");
    // tmp_sessions: flag bit 0 not set, so no field here.
    Check(b.Int32() == 20000, "call_receive_timeout_ms == 20000 (BuildConfig)");
    Check(b.Int32() == 90000, "call_ring_timeout_ms == 90000 (BuildConfig)");
    Check(b.Int32() == 30000, "call_connect_timeout_ms == 30000 (BuildConfig)");
    Check(b.Int32() == 10000, "call_packet_timeout_ms == 10000 (BuildConfig)");
    Check(DecodeTLString(b).empty(), "me_url_prefix is unset in this port (no web-preview-link feature)");
    // autoupdate_url_prefix: flag bit 7 not set, so no field here.
    Check(DecodeTLString(b) == "gif", "gif_search_username == \"gif\" (BuildConfig)");
    Check(b.Int32() == 1024, "caption_length_max == 1024 (BuildConfig)");
    Check(b.Int32() == 4096, "message_length_max == 4096 (BuildConfig)");
    Check(b.Int32() == 3, "webfile_dc_id matches this_dc (BuildConfig)");
    Check(b.PeekID() == 0x1b2286b8, "reactions_default is a real reactionEmoji#1b2286b8");
    b.ConsumeID(0x1b2286b8);
    Check(DecodeTLString(b) == "\xF0\x9F\x91\x8D", "reactions_default.emoticon is U+1F44D \"\xF0\x9F\x91\x8D\" (BuildConfig)");

    Check(b.buf.empty(), "the encoded Config has no leftover bytes (every field accounted for)");
}

void TestHelpGetConfigRequestHasNoFields() {
    TLBuffer b; // empty -- the real request carries nothing at all
    HelpGetConfigRequest req;
    req.DecodeBare(b); // must not throw or consume anything
    Check(b.buf.empty(), "HelpGetConfigRequest::DecodeBare consumes nothing (help.getConfig has no fields)");
}

} // namespace

int main() {
    TestHelpGetConfigRequestHasNoFields();
    TestConfigEncodesGoSourceValues();
    if (g_failures == 0) {
        std::printf("all mtproto help.getConfig tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto help.getConfig test(s) failed\n", g_failures);
    return 1;
}
