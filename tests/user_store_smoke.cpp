// Manual smoke test against a real Postgres instance. Not run by `ctest`
// (needs live credentials); invoke directly:
//
//   SHUZAGRAM_PG_DSN="host=127.0.0.1 port=15432 dbname=telesrv_main \
//     user=telesrv password=..." ./build/tests/user_store_smoke
//
// Phase 1 reads an existing row (id 777000, the built-in system account, in
// practice) read-only. Phase 2 creates one throwaway user, drives every
// mutation in store::IUserStore against it, and deletes it again -- the
// `users_delete_peer_username` trigger cleans up the peer_usernames row the
// UpdateUsername step creates, so no state survives a successful run.
//
// NOTE: this process calls std::_Exit() instead of returning from main().
// The Ubuntu 26.04 libpqxx 7.10.0 package double-frees a static string
// during global destruction, independent of anything in this codebase --
// confirmed with a ~10-line program that does nothing but
// `pqxx::connection(dsn)` and one query. _Exit() skips static destructors
// entirely, which is safe here (the process is terminating and the OS
// reclaims everything), but is not a fix: a long-running server process
// linking this libpqxx build would need to either pin a different libpqxx
// version or track the upstream fix.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "shuzagram/domain/phone.hpp"
#include "shuzagram/domain/user_errors.hpp"
#include "shuzagram/store/postgres/user_store.hpp"

namespace {

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    } else {
        std::printf("ok: %s\n", what.c_str());
    }
}

void ReadOnlyPhase(shuzagram::store::postgres::Database& db, shuzagram::store::postgres::UserStore& store) {
    pqxx::work probe(db.conn());
    const auto row = probe.exec("SELECT id FROM users ORDER BY id LIMIT 1");
    probe.commit();
    if (row.empty()) {
        std::printf("users table is empty, skipping read-only phase\n");
        return;
    }
    const std::int64_t id = row[0][0].as<std::int64_t>();

    const auto user = store.ByID(id);
    Check(user.has_value(), "ByID(existing row) finds it");
    if (user) {
        std::printf("  -> id=%lld first_name=%s username=%s bot=%d premium_until=%d deleted=%d\n",
                    static_cast<long long>(id), user->first_name.c_str(), user->username.c_str(), user->bot,
                    user->premium_until, user->deleted);
    }

    const auto by_ids = store.ByIDs({id});
    Check(by_ids.size() == 1 && by_ids[0].id == id, "ByIDs([existing row]) returns exactly that row");
}

// Runs the full mutation surface against one throwaway user, then deletes
// it. Returns via the Check() failure counter; cleanup always runs.
void MutationPhase(shuzagram::store::postgres::Database& db, shuzagram::store::postgres::UserStore& store) {
    using namespace shuzagram::domain;

    const std::int64_t access_hash =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();

    User draft;
    draft.access_hash = access_hash;
    draft.first_name = "SmokeTest";
    draft.country_code = "XX";
    const User created = store.Create(draft);
    const std::int64_t id = created.id;
    std::printf("created throwaway user id=%lld\n", static_cast<long long>(id));

    try {
        Check(created.first_name == "SmokeTest" && created.username.empty(), "Create sets first_name, no username");

        const User profile = store.UpdateProfile(id, "Alice", "Smith", "hello from the smoke test");
        Check(profile.first_name == "Alice" && profile.last_name == "Smith" &&
                  profile.about == "hello from the smoke test",
              "UpdateProfile applies all three fields");

        const std::string username = "shuzagram_smoke_" + std::to_string(id);
        const User named = store.UpdateUsername(id, username);
        Check(named.username == username, "UpdateUsername sets the editable slot");
        const auto resolved = store.ByUsername(username);
        Check(resolved.has_value() && resolved->id == id, "ByUsername resolves the new username back to id");

        const std::string phone = "888" + std::to_string(id);
        Check(ValidPhone(phone), "constructed +888 virtual phone is canonical (test precondition)");
        const User withPhone = store.UpdatePhone(id, phone);
        Check(withPhone.phone == phone, "UpdatePhone sets the login identity");

        const User scammed = store.SetScamFake(id, /*scam=*/true, /*fake=*/false);
        Check(scammed.scam && !scammed.fake, "SetScamFake(true, false) applies");
        const User unflagged = store.SetScamFake(id, false, false);
        Check(!unflagged.scam && !unflagged.fake, "SetScamFake(false, false) clears it");
        try {
            store.SetScamFake(id, true, true);
            Check(false, "SetScamFake(true, true) should throw");
        } catch (const PeerModerationFlagsInvalidError&) {
            Check(true, "SetScamFake(true, true) throws PeerModerationFlagsInvalidError");
        }

        const User birthday = store.UpdateBirthday(id, Birthday{15, 6, 2000});
        Check(birthday.birthday == Birthday{15, 6, 2000}, "UpdateBirthday applies");

        const User channel = store.UpdatePersonalChannel(id, 0);
        Check(channel.personal_channel_id == 0, "UpdatePersonalChannel(0) is a no-op clear");

        const User colored = store.UpdateColor(id, /*for_profile=*/false, PeerColor{true, 5, 0});
        Check(colored.color == PeerColor{true, 5, 0} && colored.profile_color.Empty(),
              "UpdateColor(for_profile=false) touches only `color`");
        const User profileColored = store.UpdateColor(id, /*for_profile=*/true, PeerColor{true, 7, 0});
        Check(profileColored.profile_color == PeerColor{true, 7, 0} &&
                  profileColored.color == PeerColor{true, 5, 0},
              "UpdateColor(for_profile=true) touches only `profile_color`, leaving `color` alone");

        UserEmojiStatus plainStatus;
        plainStatus.document_id = 123456789;
        plainStatus.until = 0;
        const User statused = store.UpdateEmojiStatus(id, plainStatus);
        Check(statused.emoji_status_document_id == 123456789 && statused.emoji_status_until == 0,
              "UpdateEmojiStatus applies a plain (non-collectible) status");

        UserEmojiStatus collectibleStatus = plainStatus;
        collectibleStatus.collectible.collectible_id = 1;
        collectibleStatus.collectible.document_id = plainStatus.document_id;
        collectibleStatus.collectible.title = "Test Gift";
        collectibleStatus.collectible.slug = "test-gift";
        collectibleStatus.collectible.pattern_document_id = 2;
        try {
            store.UpdateEmojiStatus(id, collectibleStatus);
            Check(false, "UpdateEmojiStatus(collectible) should throw NotImplementedError");
        } catch (const NotImplementedError&) {
            Check(true, "UpdateEmojiStatus(collectible) throws NotImplementedError (star-gift module not ported)");
        }

        const int past = static_cast<int>(std::time(nullptr)) - 3600;
        store.SetPremiumUntil(id, past);
        const auto swept = store.SweepExpiredPremium(std::time(nullptr), 1000);
        bool found = false;
        for (const auto& u : swept) {
            if (u.id == id) found = true;
        }
        Check(found, "SweepExpiredPremium clears our already-expired row");
        const auto afterSweep = store.ByID(id);
        Check(afterSweep.has_value() && afterSweep->premium_until == 0, "premium_until reads back as 0 after sweep");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "FAIL: unexpected exception during mutation phase: %s\n", e.what());
        ++g_failures;
    }

    pqxx::work cleanup(db.conn());
    cleanup.exec("DELETE FROM users WHERE id = $1", pqxx::params{id});
    cleanup.commit();
    std::printf("cleaned up throwaway user id=%lld\n", static_cast<long long>(id));
}

} // namespace

int main() {
    const char* dsn = std::getenv("SHUZAGRAM_PG_DSN");
    if (!dsn) {
        std::printf("SHUZAGRAM_PG_DSN not set, skipping live smoke test\n");
        return 0;
    }

    shuzagram::store::postgres::Database db(dsn);
    shuzagram::store::postgres::UserStore store(db);

    ReadOnlyPhase(db, store);
    MutationPhase(db, store);

    std::fflush(stdout);
    if (g_failures == 0) {
        std::printf("smoke test passed\n");
        std::fflush(stdout);
        std::_Exit(0); // see the libpqxx-teardown note above
    }
    std::fprintf(stderr, "%d smoke check(s) failed\n", g_failures);
    std::_Exit(1);
}
