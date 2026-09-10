// App-side license gates in the host executable. Together these make the host
// treat the license as valid without contacting any server:
//   - hold the grace-timer global at 0 after startup init
//   - force the login-state enum to 0 and keep the license string non-empty
//   - make the manager reply-status check always pass
//   - force the license verdict to 0 at its source (the parser)
//   - flip the license-string exit branches to continue
#include "hooks.h"
#include "sigscan.h"
#include "detour_util.h"

namespace {

// License object/context field offsets, in bytes.
constexpr unsigned kVerdictPrimary   = 0x48;  // parser state enum (0 == licensed)
constexpr unsigned kVerdictSecondary = 0x4C;  // companion enum
constexpr unsigned kCtxState         = 0x500; // login-state enum at ctx+0x500

// RIP-relative operand layout of `mov reg, [rip+disp32]` / `cmp byte [rip+disp32], imm8`.
constexpr int kMovDispOff  = 2, kMovLen = 6;  // 89 05 <disp32>
constexpr int kCmpDispOff  = 2, kCmpLen = 7;  // 80 3D <disp32> <imm8>

// The reply-status compare immediate to raise: overwrite the low word of the
// `mov eax, 0x190` (imm32 starts one byte past the B8 opcode).
constexpr int kMovImmLowOff = 1;

constexpr uint8_t kJmpShort = 0xEB; // rel8 JMP, overwrites the JNZ (0x75) opcode

// -- grace-timer global -----------------------------------------------------
using init_t = void*(*)(void*, void*, void*, void*);
init_t Real_init = nullptr;
volatile LONG* g_grace = nullptr;

void clear_grace() { if (g_grace) *g_grace = 0; }

/// Run the original startup init, then keep the grace-timer global at 0.
void* Hook_init(void* a, void* b, void* c, void* d) {
    void* r = Real_init(a, b, c, d);
    clear_grace();
    return r;
}
constexpr char SIG_INIT_CALL[] =
    "E8 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8D 8D"; // WinMain call site
constexpr char SIG_SEED[] = "89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 44 89 35";  // mov <grace>, eax

// -- login-state poll -------------------------------------------------------
using poll_t = char(*)(void*, char);
poll_t Real_poll = nullptr;

// The buffer whose emptiness the "license present" gates test; kept non-empty.
volatile char* g_licstr = nullptr;
constexpr char kLicText[] = "Offline";

/// Run the original poll, then force the login state active and the license
/// string non-empty.
char Hook_poll(void* ctx, char poll_only) {
    char r = Real_poll(ctx, poll_only);
    if (ctx)
        *reinterpret_cast<volatile LONG*>(static_cast<uint8_t*>(ctx) + kCtxState) = 0;
    if (g_licstr && g_licstr[0] == 0)
        for (size_t i = 0; i < sizeof(kLicText); ++i) g_licstr[i] = kLicText[i];
    return r;
}
constexpr char SIG_POLL[] =
    "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 48 8B D9 0F B6 F2";

// -- manager reply-status threshold -----------------------------------------
constexpr char SIG_REPLY_THRESHOLD[] = "B8 90 01 00 00 66 44 3B E8"; // mov eax,0x190; cmp

// -- verdict source (three identical parser clones) -------------------------
using parser_t = long long(*)(void*, void*, void*);
parser_t Real_parser[3] = {nullptr, nullptr, nullptr};

/// Zero the state enum the parser wrote into its result object.
void force_verdict(void* obj) {
    auto* p = static_cast<uint8_t*>(obj);
    *reinterpret_cast<volatile LONG*>(p + kVerdictPrimary) = 0;
    *reinterpret_cast<volatile LONG*>(p + kVerdictSecondary) = 0;
}
long long Hook_parser0(void* o, void* a, void* b) { long long r = Real_parser[0](o,a,b); force_verdict(o); return r; }
long long Hook_parser1(void* o, void* a, void* b) { long long r = Real_parser[1](o,a,b); force_verdict(o); return r; }
long long Hook_parser2(void* o, void* a, void* b) { long long r = Real_parser[2](o,a,b); force_verdict(o); return r; }

// One signature matching all three clones (match == function entry); the only
// wildcard is the security-cookie displacement.
constexpr char SIG_PARSER[] =
    "48 8B C4 48 89 58 20 55 56 57 41 54 41 55 41 56 41 57 48 8D A8 08 FA FF FF "
    "48 81 EC C0 06 00 00 C5 F8 29 70 B8 C5 F8 29 78 A8 48 8B 05 ?? ?? ?? ?? "
    "48 33 C4 48 89 85 90 05 00 00 49 8B F0 4C 89";

// -- license-string exit branches in WinMain --------------------------------
// Each site is `cmp byte[rip+licstr], 0 ; jnz continue ; <_exit x3>`. Flip the
// JNZ to a JMP so the continue path is always taken. The offset is from the
// signature match to that JNZ opcode.
constexpr char SIG_LIC_B[] = "80 3D ?? ?? ?? ?? ?? 75 ?? 33 C9 C5 F8 77";
constexpr char SIG_LIC_C[] =
    "41 B0 01 33 D2 48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? ?? 75";
constexpr char SIG_LIC_D[] = "40 38 3D ?? ?? ?? ?? 75 ?? 33 C9 E8";
constexpr int kLicB_JnzOff = 7, kLicC_JnzOff = 24, kLicD_JnzOff = 7;

} // namespace

bool install_app_hooks() {
    HMODULE app = GetModuleHandleW(nullptr);
    if (!app) return false;
    bool ok = true;

    // Hold the grace-timer global (from `mov <grace>, eax`) at 0.
    if (uint8_t* seed = sig_scan_unique(app, SIG_SEED))
        g_grace = reinterpret_cast<volatile LONG*>(rip_target(seed, kMovDispOff, kMovLen));
    else
        fb_log(FB_TAG "app: grace global not found");
    uint8_t* call = sig_scan_unique(app, SIG_INIT_CALL);
    Real_init = call ? reinterpret_cast<init_t>(rel32_target(call)) : nullptr;
    clear_grace();
    if (Real_init) ok &= attach(reinterpret_cast<void**>(&Real_init), Hook_init, "app-init");
    else fb_log(FB_TAG "app: init not found");

    // Login-state poll.
    Real_poll = reinterpret_cast<poll_t>(sig_scan_unique(app, SIG_POLL));
    if (Real_poll) ok &= attach(reinterpret_cast<void**>(&Real_poll), Hook_poll, "app-login");
    else fb_log(FB_TAG "app: login poll not found");

    // Raise the reply-status threshold so every reply counts as success.
    if (uint8_t* thr = sig_scan_unique(app, SIG_REPLY_THRESHOLD)) {
        const uint8_t max_status[2] = {0xFF, 0xFF}; // 0x0190 -> 0xFFFF
        if (!write_code(thr + kMovImmLowOff, max_status, sizeof(max_status)))
            fb_log(FB_TAG "app-reply: patch failed");
    } else {
        fb_log(FB_TAG "app-reply: threshold site not found");
    }

    // Force the verdict to 0 in every parser clone.
    uint8_t* clones[3] = {nullptr, nullptr, nullptr};
    int n = sig_scan_all(app, SIG_PARSER, clones, 3);
    void* hooks[3] = {reinterpret_cast<void*>(Hook_parser0),
                      reinterpret_cast<void*>(Hook_parser1),
                      reinterpret_cast<void*>(Hook_parser2)};
    for (int i = 0; i < n; ++i) {
        Real_parser[i] = reinterpret_cast<parser_t>(clones[i]);
        ok &= attach(reinterpret_cast<void**>(&Real_parser[i]), hooks[i], "app-verdict");
    }
    if (n == 0) { ok = false; fb_log(FB_TAG "app: parser clones not found"); }

    // Patch the three WinMain license-string branches to always continue.
    auto patch_branch = [&](const char* sig, int jnz_off, const char* tag) -> uint8_t* {
        uint8_t* m = sig_scan_unique(app, sig);
        if (!m) { fb_log(FB_TAG "%s not found", tag); return nullptr; }
        write_code(m + jnz_off, &kJmpShort, 1);
        return m;
    };
    if (uint8_t* sb = patch_branch(SIG_LIC_B, kLicB_JnzOff, "app-licstr B")) // site B also
        g_licstr = reinterpret_cast<volatile char*>(rip_target(sb, kCmpDispOff, kCmpLen)); // yields the buffer
    patch_branch(SIG_LIC_C, kLicC_JnzOff, "app-licstr C");
    patch_branch(SIG_LIC_D, kLicD_JnzOff, "app-licstr D");

    return ok;
}
