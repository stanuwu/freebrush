// Thin wrappers around a single-hook Detours transaction.
#pragma once

#include "common.h"
#include <detours.h>

/// Attach one detour in its own transaction. `real` is updated in place to the
/// callable trampoline. Returns true on success.
inline bool attach(void** real, void* hook, const char* name) {
    if (!*real || !hook) {
        fb_log(FB_TAG "%s: null target, skipped", name);
        return false;
    }
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    LONG e = DetourAttach(real, hook);
    if (e != NO_ERROR) {
        DetourTransactionAbort();
        fb_log(FB_TAG "%s: attach failed (%ld)", name, e);
        return false;
    }
    e = DetourTransactionCommit();
    if (e != NO_ERROR) {
        fb_log(FB_TAG "%s: commit failed (%ld)", name, e);
        return false;
    }
    return true;
}
