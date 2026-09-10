// Hook install entry points. Each returns true if its hooks were attached.
#pragma once

#include "common.h"

/// Fail non-loopback connects so all server traffic takes the offline path.
bool install_net_hooks(HMODULE ws2_32);

/// No-op the manager handshake so it never opens the local IPC pipe; this
/// avoids the fatal "manager not installed" exit.
bool install_service_hooks(HMODULE licensing_module);

/// Force the host to treat the license as valid (hooks in the host executable).
bool install_app_hooks();
