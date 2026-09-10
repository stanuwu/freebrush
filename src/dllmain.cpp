// Entry point and orchestration for the offline-enable helper.
//
// Load vector: this builds as "version.dll" and is dropped in the app folder.
// The app-directory search order loads it before the system copy. At load it
// resolves the real system version.dll and routes every version export to it
// (see proxy.cpp / thunks.asm), so version queries keep working.
//
// The host executable is already mapped at attach, so its hooks install
// immediately. Hooks that live in other modules are installed the moment that
// module is mapped, via a loader DLL-load notification (no polling).
#include "common.h"
#include "hooks.h"
#include "proxy.h"
#include <winternl.h>
#include <detours.h>
#include <cstdio>
#include <cstdarg>

void fb_log(const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    OutputDebugStringA(buf);
}

namespace {

// Loader DLL-load notification (ntdll), declared locally as the SDK omits it.
struct LDR_DLL_NOTIFICATION_DATA {
    ULONG Flags;
    const UNICODE_STRING* FullDllName;
    const UNICODE_STRING* BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
};
using PLDR_NOTIFY = VOID(CALLBACK*)(ULONG, const LDR_DLL_NOTIFICATION_DATA*, PVOID);
using LdrRegister_t = NTSTATUS(NTAPI*)(ULONG, PLDR_NOTIFY, PVOID, PVOID*);
constexpr ULONG kDllLoaded = 1; // LDR_DLL_NOTIFICATION_REASON_LOADED

PVOID g_ldr_cookie = nullptr;

/// A module whose hooks install once it is mapped, matched by base name.
struct ModuleHook {
    const wchar_t* name;
    bool (*install)(HMODULE);
    bool done;
};
ModuleHook g_module_hooks[] = {
    {L"ws2_32.dll",             install_net_hooks,     false},
    {L"licensing.module.xdl64", install_service_hooks, false},
};

/// Case-insensitive equality of a UNICODE_STRING to a wide C string.
bool name_is(const UNICODE_STRING* u, const wchar_t* name) {
    size_t len = u->Length / sizeof(wchar_t);
    return _wcsnicmp(u->Buffer, name, len) == 0 && name[len] == 0;
}

/// Install any pending module's hooks now that it is mapped.
void on_dll_loaded(ULONG reason, const LDR_DLL_NOTIFICATION_DATA* data, PVOID) {
    if (reason != kDllLoaded || !data || !data->BaseDllName || !data->BaseDllName->Buffer)
        return;
    for (auto& mh : g_module_hooks)
        if (!mh.done && name_is(data->BaseDllName, mh.name)) {
            mh.done = true;
            mh.install(reinterpret_cast<HMODULE>(data->DllBase));
        }
}

} // namespace

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        proxy_init();        // route the version exports to the real library
        install_app_hooks(); // the host executable is already mapped

        // Subscribe to future module loads, then catch any already mapped.
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto reg = ntdll ? reinterpret_cast<LdrRegister_t>(
                               GetProcAddress(ntdll, "LdrRegisterDllNotification"))
                         : nullptr;
        if (reg) reg(0, on_dll_loaded, nullptr, &g_ldr_cookie);
        for (auto& mh : g_module_hooks)
            if (!mh.done)
                if (HMODULE h = GetModuleHandleW(mh.name)) { mh.done = true; mh.install(h); }
    }
    return TRUE;
}
