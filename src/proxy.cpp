// Runtime forwarding of the version API to the real system library.
// The exported symbols are jmp thunks in proxy.asm, each jumping through
// g_real[i]; proxy_init resolves the real system version.dll and fills g_real.
#include "common.h"
#include "proxy.h"

// Export the forwarded names (defined as thunks in proxy.asm).
#pragma comment(linker, "/EXPORT:GetFileVersionInfoA")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoByHandle")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExA")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExW")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeA")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExA")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExW")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeW")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoW")
#pragma comment(linker, "/EXPORT:VerFindFileA")
#pragma comment(linker, "/EXPORT:VerFindFileW")
#pragma comment(linker, "/EXPORT:VerInstallFileA")
#pragma comment(linker, "/EXPORT:VerInstallFileW")
#pragma comment(linker, "/EXPORT:VerQueryValueA")
#pragma comment(linker, "/EXPORT:VerQueryValueW")

extern "C" void* g_real[PROXY_COUNT] = {nullptr};

namespace {
// Order MUST match the thunk indices in proxy.asm.
const char* const kNames[PROXY_COUNT] = {
    "GetFileVersionInfoA",        // 0
    "GetFileVersionInfoByHandle", // 1
    "GetFileVersionInfoExA",      // 2
    "GetFileVersionInfoExW",      // 3
    "GetFileVersionInfoSizeA",    // 4
    "GetFileVersionInfoSizeExA",  // 5
    "GetFileVersionInfoSizeExW",  // 6
    "GetFileVersionInfoSizeW",    // 7
    "GetFileVersionInfoW",        // 8
    "VerFindFileA",               // 9
    "VerFindFileW",               // 10
    "VerInstallFileA",            // 11
    "VerInstallFileW",            // 12
    "VerQueryValueA",             // 13
    "VerQueryValueW",             // 14
};
} // namespace

extern "C" void proxy_init() {
    wchar_t path[MAX_PATH];
    UINT n = GetSystemDirectoryW(path, MAX_PATH); // e.g. C:\Windows\System32
    if (n == 0 || n >= MAX_PATH - 16) { fb_log(FB_TAG "proxy: sysdir failed"); return; }
    wcscat_s(path, MAX_PATH, L"\\version.dll");

    HMODULE real = LoadLibraryW(path); // the genuine system library
    if (!real) { fb_log(FB_TAG "proxy: real version.dll not found"); return; }

    for (int i = 0; i < PROXY_COUNT; ++i) {
        g_real[i] = reinterpret_cast<void*>(GetProcAddress(real, kNames[i]));
        if (!g_real[i]) fb_log(FB_TAG "proxy: missing %s", kNames[i]);
    }
}
