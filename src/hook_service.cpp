// No-op the manager handshake so it never opens the IPC pipe. The pipe opener
// throws on failure, which the framework turns into a fatal exit; skipping the
// handshake leaves the graceful "no manager license" state.
#include "hooks.h"
#include "sigscan.h"
#include "detour_util.h"

namespace {

using handshake_t = void(*)(void*);
handshake_t Real_handshake = nullptr;

/// Replacement handshake: do nothing.
void Hook_handshake(void*) {}

// String the handshake builds; its unique reference locates the function.
constexpr char kAnchor[] = "/mxo/v1/authorize";

} // namespace

bool install_service_hooks(HMODULE licensing_module) {
    if (!licensing_module) return false;

    uint8_t* str = find_bytes(licensing_module, kAnchor, sizeof(kAnchor)); // incl. NUL
    if (!str) { fb_log(FB_TAG "service: anchor string not found"); return false; }

    uint8_t* ref = find_rip_lea_ref(licensing_module, str);
    uint8_t* fn = ref ? function_start(licensing_module, ref) : nullptr;
    Real_handshake = reinterpret_cast<handshake_t>(fn);

    return attach(reinterpret_cast<void**>(&Real_handshake), Hook_handshake,
                  "manager-handshake-bypass");
}
