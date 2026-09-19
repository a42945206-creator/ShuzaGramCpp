// Wire-format checks for account.updateStatus (messages/account.hpp) and the
// new bare-Bool decoder (messages/bool.hpp), same discipline as the other
// mtproto_*_test.cpp files: exact constructor ids, copied from gotd/td
// (tg/tl_account_update_status_gen.go), not invented.

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

} // namespace

int main() {
    TestDecodeBoolRoundTrip();
    TestDecodeBoolRejectsUnknownId();
    TestDecodeAccountUpdateStatusRequest();
    if (g_failures == 0) {
        std::printf("all mtproto account tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto account test(s) failed\n", g_failures);
    return 1;
}
