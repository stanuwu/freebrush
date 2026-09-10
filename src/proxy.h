// Runtime proxy for the version API: resolve the real system library so the
// exported jmp thunks (proxy.asm) can forward to it.
#pragma once

/// Number of forwarded version exports.
#define PROXY_COUNT 15

extern "C" {
/// Resolved real function pointers, indexed to match proxy.asm and proxy.cpp.
extern void* g_real[PROXY_COUNT];

/// Load the real system version.dll and fill g_real. Call once at attach,
/// before any forwarded export can run.
void proxy_init();
}
