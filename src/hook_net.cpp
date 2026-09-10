// Fail every non-loopback outbound connect so server calls take the offline
// path. Loopback must pass through: the network module uses an internal
// 127.0.0.1 socket pair for thread wakeups.
#include "hooks.h"
#include "detour_util.h"

namespace {

using connect_t = int(WSAAPI*)(SOCKET, const sockaddr*, int);
connect_t Real_connect = nullptr;

constexpr uint32_t kLoopbackNet = 127; // first octet of 127.0.0.0/8

/// True for 127.0.0.0/8 or ::1.
bool is_loopback(const sockaddr* a) {
    if (!a) return false;
    if (a->sa_family == AF_INET) {
        auto* s = reinterpret_cast<const sockaddr_in*>(a);
        return (ntohl(s->sin_addr.s_addr) >> 24) == kLoopbackNet;
    }
    if (a->sa_family == AF_INET6) {
        auto* s6 = reinterpret_cast<const sockaddr_in6*>(a);
        static const unsigned char in6addr_lo[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        return memcmp(&s6->sin6_addr, in6addr_lo, 16) == 0;
    }
    return false;
}

int WSAAPI Hook_connect(SOCKET s, const sockaddr* name, int namelen) {
    if (is_loopback(name)) return Real_connect(s, name, namelen);
    WSASetLastError(WSAETIMEDOUT); // look like a dead network, not a hard refusal
    return SOCKET_ERROR;
}

} // namespace

bool install_net_hooks(HMODULE ws2_32) {
    if (!ws2_32) return false;
    Real_connect = reinterpret_cast<connect_t>(GetProcAddress(ws2_32, "connect"));
    return attach(reinterpret_cast<void**>(&Real_connect), Hook_connect, "connect");
}
