// Shared includes, logging, and small helpers for the helper module.
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdint>

/// Write a one-line debug string, prefixed, to the debugger output.
void fb_log(const char* fmt, ...);

/// Prefix used for all debug output from this module.
#define FB_TAG "[fb] "
